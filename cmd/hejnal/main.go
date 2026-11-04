// Command hejnal watches an organisation's internet-facing systems for
// software that attackers are exploiting right now.
//
// It finds the organisation's hosts inside an authorised scope, identifies the
// software they run, matches it against CISA's Known Exploited
// Vulnerabilities catalog and writes a prioritised fix list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/epss"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/nvd"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/version"
)

const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

const usage = `Hejnal watches your internet-facing systems for software that attackers
are exploiting right now, and tells you what to fix first.

Usage:
  hejnal init      [-scope scope.json]          write an example scope file
  hejnal run       [-scope scope.json] [flags]  discover, match and report in one go
  hejnal discover  [-scope scope.json] [flags]  find hosts and identify their software
  hejnal feeds     [flags]                      download the CISA KEV catalog
  hejnal match     [flags]                      match the last inventory against the catalog
  hejnal report    fixlist|nis2|monthly [flags] print a report from the saved runs
  hejnal rules                                  list the products Hejnal recognises
  hejnal version

Run "hejnal <command> -h" for the flags of a command.

Exit status: 0 when done, 1 on errors, 2 when "run -fail-on" finds new
problems at or above the given severity.

Only check systems you own or have written permission to test.
`

// errUsage marks command-line mistakes the flag package has already reported.
var errUsage = errors.New("usage")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := newApp(os.Stdout, os.Stderr).run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

type app struct {
	stdout, stderr io.Writer
	stdin          io.Reader
	now            func() time.Time
	client         *http.Client
	resolver       discover.Resolver // nil uses the system resolver
	kevURL         string
	epssURL        string
	ctURL          string
	nvdURL         string

	logMu sync.Mutex
}

func newApp(stdout, stderr io.Writer) *app {
	return &app{
		stdout:  stdout,
		stderr:  stderr,
		stdin:   os.Stdin,
		now:     time.Now,
		client:  &http.Client{Timeout: 2 * time.Minute},
		kevURL:  kev.DefaultURL,
		epssURL: epss.DefaultAPI,
		ctURL:   discover.CrtShURL,
		nvdURL:  nvd.DefaultAPI,
	}
}

func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := exitOK
	switch cmd {
	case "init":
		err = a.cmdInit(rest)
	case "run":
		code, err = a.cmdRun(ctx, rest)
	case "discover":
		err = a.cmdDiscover(ctx, rest)
	case "feeds":
		err = a.cmdFeeds(ctx, rest)
	case "match":
		err = a.cmdMatch(ctx, rest)
	case "report":
		err = a.cmdReport(rest)
	case "rules":
		err = a.cmdRules(rest)
	case "version", "-version", "--version":
		fmt.Fprintln(a.stdout, "hejnal", version.Version)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(a.stdout, usage)
	default:
		fmt.Fprintf(a.stderr, "hejnal: unknown command %q\n\n%s", cmd, usage)
		return exitError
	}
	switch {
	case err == nil:
		return code
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errUsage):
		return exitError
	}
	fmt.Fprintln(a.stderr, "hejnal:", err)
	return exitError
}

// options holds every flag; each command registers the ones it uses.
type options struct {
	scope       string
	stateDir    string
	cacheDir    string
	kevFile     string
	offline     bool
	noEPSS      bool
	noNVD       bool
	noCT        bool
	checks      bool
	lang        string
	webhook     string
	teams       string
	emailTo     string
	failOn      string
	concurrency int
	timeout     time.Duration
	out         string
}

func (o *options) stateFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.stateDir, "state", ".hejnal", "directory that keeps results between runs")
}

func (o *options) cacheFlag(fs *flag.FlagSet) {
	fs.StringVar(&o.cacheDir, "cache", "", "directory for downloaded feeds (default <state>/cache)")
}

func (o *options) feedFlags(fs *flag.FlagSet) {
	o.cacheFlag(fs)
	fs.StringVar(&o.kevFile, "kev-file", "", "read the KEV catalog from this file instead of downloading it")
	fs.BoolVar(&o.offline, "offline", false, "do not download feeds; use the cached copies")
	fs.BoolVar(&o.noEPSS, "no-epss", false, "do not use EPSS exploit-probability scores")
	fs.BoolVar(&o.noNVD, "no-nvd", false, "do not compare versions with NVD's affected ranges")
}

func (o *options) scanFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.scope, "scope", "scope.json", "scope file listing the systems you are authorised to check")
	fs.BoolVar(&o.noCT, "no-ct", false, "do not look up subdomains in certificate transparency logs")
	fs.IntVar(&o.concurrency, "concurrency", 16, "parallel connections")
	fs.DurationVar(&o.timeout, "timeout", 8*time.Second, "timeout for each connection and response")
	fs.BoolVar(&o.checks, "checks", false, "also check fixed paths for exposed files (.git, .env, server-status) and product versions")
}

func (o *options) langFlag(fs *flag.FlagSet) {
	fs.StringVar(&o.lang, "lang", "en", "report language: en or pl")
}

func (o *options) check() error {
	if o.lang != "" && !report.ValidLang(o.lang) {
		return fmt.Errorf("unknown language %q: use %s", o.lang, strings.Join(report.Languages, " or "))
	}
	if o.concurrency < 0 || o.concurrency > 256 {
		return fmt.Errorf("-concurrency must be between 1 and 256")
	}
	return nil
}

// engine builds an engine from the flags.
func (a *app) engine(o *options) (*engine.Engine, error) {
	return engine.New(engine.Config{
		StateDir:    o.stateDir,
		CacheDir:    o.cacheDir,
		KEVFile:     o.kevFile,
		KEVURL:      a.kevURL,
		EPSSURL:     a.epssURL,
		CTURL:       a.ctURL,
		Offline:     o.offline,
		NoEPSS:      o.noEPSS,
		NoCT:        o.noCT,
		NoNVD:       o.noNVD,
		Checks:      o.checks,
		NVDURL:      a.nvdURL,
		NVDKey:      os.Getenv("HEJNAL_NVD_API_KEY"),
		Concurrency: o.concurrency,
		Timeout:     o.timeout,
		HTTPClient:  a.client,
		Resolver:    a.resolver,
		Now:         a.now,
		Logf:        a.logf,
	})
}

func (a *app) flags(name, synopsis, about string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "Usage: hejnal %s %s\n\n%s\n\nFlags:\n", name, synopsis, about)
		fs.PrintDefaults()
	}
	return fs
}

func (a *app) parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(a.stderr, "hejnal %s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		fs.Usage()
		return errUsage
	}
	return nil
}

func (a *app) logf(format string, args ...any) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	fmt.Fprintf(a.stderr, "hejnal: "+format+"\n", args...)
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}
