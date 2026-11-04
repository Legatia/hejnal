// Command hejnal watches an organisation's internet-facing systems for
// software that attackers are exploiting right now.
//
// It finds the organisation's hosts inside an authorised scope, identifies the
// software they run, matches it against CISA's Known Exploited
// Vulnerabilities catalog and writes a prioritised fix list.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/Legatia/hejnal/internal/discover"
	"github.com/Legatia/hejnal/internal/epss"
	"github.com/Legatia/hejnal/internal/fingerprint"
	"github.com/Legatia/hejnal/internal/inventory"
	"github.com/Legatia/hejnal/internal/kev"
	"github.com/Legatia/hejnal/internal/match"
	"github.com/Legatia/hejnal/internal/notify"
	"github.com/Legatia/hejnal/internal/report"
	"github.com/Legatia/hejnal/internal/scope"
	"github.com/Legatia/hejnal/internal/state"
	"github.com/Legatia/hejnal/internal/version"
)

const (
	kevMaxAge  = 6 * time.Hour
	epssMaxAge = 24 * time.Hour

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
  hejnal report    fixlist|nis2 [flags]         print a report from the last run
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
	now            func() time.Time
	client         *http.Client
	resolver       discover.Resolver // nil uses the system resolver
	kevURL         string
	epssURL        string
	ctURL          string

	logMu sync.Mutex
}

func newApp(stdout, stderr io.Writer) *app {
	return &app{
		stdout:  stdout,
		stderr:  stderr,
		now:     time.Now,
		client:  &http.Client{Timeout: 2 * time.Minute},
		kevURL:  kev.DefaultURL,
		epssURL: epss.DefaultAPI,
		ctURL:   discover.CrtShURL,
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
	noCT        bool
	lang        string
	webhook     string
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
}

func (o *options) scanFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.scope, "scope", "scope.json", "scope file listing the systems you are authorised to check")
	fs.BoolVar(&o.noCT, "no-ct", false, "do not look up subdomains in certificate transparency logs")
	fs.IntVar(&o.concurrency, "concurrency", 16, "parallel connections")
	fs.DurationVar(&o.timeout, "timeout", 8*time.Second, "timeout for each connection and response")
}

func (o *options) langFlag(fs *flag.FlagSet) {
	fs.StringVar(&o.lang, "lang", "en", "report language: en or pl")
}

func (o *options) cache() string {
	if o.cacheDir != "" {
		return o.cacheDir
	}
	return filepath.Join(o.stateDir, "cache")
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

func (a *app) cmdInit(args []string) error {
	fs := a.flags("init", "[-scope scope.json]", "Write an example scope file to edit.")
	path := fs.String("scope", "scope.json", "where to write the scope file")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	data, err := json.MarshalIndent(scope.Example(a.now()), "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; edit it, or pass -scope with another path", *path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Wrote %s.\n\nEdit it to list your domains, hosts and IP ranges, and record who confirmed\nthat you may test them. Then run:\n\n  hejnal run -scope %s\n", *path, *path)
	return nil
}

func (a *app) loadScope(path string) (*scope.Scope, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("scope file %s not found; create one with `hejnal init`", path)
	}
	if err != nil {
		return nil, err
	}
	return scope.Parse(data, a.now())
}

func (a *app) printBanner(s *scope.Scope) {
	auth := s.Authorization
	fmt.Fprintf(a.stderr, "Hejnal %s · %s\n", version.Version, s.Organization)
	fmt.Fprintf(a.stderr, "Authorised by %s on %s: %q\n", auth.ConfirmedBy, auth.Date, auth.Statement)
	fmt.Fprintf(a.stderr, "Scope: %d domains · %d hosts · %d addresses in ranges · ports %s\n",
		len(s.Domains), len(s.Hosts), len(s.Addresses()), joinInts(s.Ports))
	fmt.Fprintln(a.stderr, "Only check systems you own or have written permission to test.")
}

func (a *app) discover(ctx context.Context, s *scope.Scope, eng *fingerprint.Engine, o *options) (*inventory.Inventory, error) {
	opts := discover.Options{
		Scope:       s,
		Engine:      eng,
		Resolver:    a.resolver,
		Concurrency: o.concurrency,
		Timeout:     o.timeout,
		UserAgent:   version.UserAgent(),
		Now:         a.now,
		Logf:        a.logf,
	}
	if !o.noCT && len(s.Domains) > 0 {
		opts.CT = &discover.CrtSh{Client: a.client, BaseURL: a.ctURL, UserAgent: version.UserAgent()}
	}
	inv, err := discover.Run(ctx, opts)
	if err != nil {
		return nil, err
	}
	assets, services, techs := inv.Counts()
	a.logf("found %d hosts, %d services and %d products", assets, services, techs)
	return inv, nil
}

func (a *app) cmdDiscover(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("discover", "[-scope scope.json] [flags]", "Find hosts in the scope and identify the software they run.")
	o.scanFlags(fs)
	o.stateFlags(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	s, err := a.loadScope(o.scope)
	if err != nil {
		return err
	}
	a.printBanner(s)
	eng, err := fingerprint.Default()
	if err != nil {
		return err
	}
	inv, err := a.discover(ctx, s, eng, o)
	if err != nil {
		return err
	}
	if err := (state.Store{Dir: o.stateDir}).SaveInventory(inv); err != nil {
		return err
	}
	assets, services, techs := inv.Counts()
	fmt.Fprintf(a.stdout, "Found %d hosts, %d services and %d products. Inventory saved to %s.\n",
		assets, services, techs, filepath.Join(o.stateDir, "inventory.json"))
	return nil
}

func (a *app) cmdFeeds(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("feeds", "[flags]", "Download the CISA Known Exploited Vulnerabilities catalog.")
	o.stateFlags(fs)
	o.cacheFlag(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	path := filepath.Join(o.cache(), "kev.json")
	cat, err := kev.Fetch(ctx, a.client, a.kevURL, version.UserAgent(), path)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "CISA KEV catalog %s: %d known exploited flaws. Saved to %s.\n",
		cat.CatalogVersion, len(cat.Vulnerabilities), path)
	return nil
}

func (a *app) loadKEV(ctx context.Context, o *options) (*kev.Catalog, error) {
	if o.kevFile != "" {
		return kev.Load(o.kevFile)
	}
	path := filepath.Join(o.cache(), "kev.json")
	if o.offline {
		cat, err := kev.Load(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no cached KEV catalog at %s: run `hejnal feeds` while online, or pass -kev-file", path)
		}
		return cat, err
	}
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < kevMaxAge {
		if cat, err := kev.Load(path); err == nil {
			return cat, nil
		}
	}
	cat, err := kev.Fetch(ctx, a.client, a.kevURL, version.UserAgent(), path)
	if err != nil {
		if cached, cerr := kev.Load(path); cerr == nil {
			a.logf("could not refresh the KEV catalog (%v); using cached catalog %s", err, cached.CatalogVersion)
			return cached, nil
		}
		return nil, err
	}
	a.logf("downloaded CISA KEV catalog %s (%d flaws)", cat.CatalogVersion, len(cat.Vulnerabilities))
	return cat, nil
}

func (a *app) loadEPSS(ctx context.Context, o *options, cves []string) map[string]epss.Score {
	if o.noEPSS || len(cves) == 0 {
		return nil
	}
	path := filepath.Join(o.cache(), "epss.json")
	cache, err := epss.LoadCache(path)
	if err != nil {
		a.logf("ignoring unreadable EPSS cache: %v", err)
		cache = map[string]epss.Score{}
	}
	if o.offline {
		return cache
	}
	fresh := false
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < epssMaxAge {
		fresh = true
	}
	var want []string
	for _, c := range cves {
		if _, ok := cache[c]; !ok || !fresh {
			want = append(want, c)
		}
	}
	if len(want) == 0 {
		return cache
	}
	scores, err := epss.Fetch(ctx, a.client, a.epssURL, version.UserAgent(), want)
	if err != nil {
		a.logf("could not fetch EPSS scores (%v); continuing without fresh scores", err)
		return cache
	}
	for k, v := range scores {
		cache[k] = v
	}
	if err := epss.SaveCache(path, cache); err != nil {
		a.logf("could not save EPSS cache: %v", err)
	}
	return cache
}

// matchInventory matches an inventory against the catalog and EPSS scores.
func (a *app) matchInventory(ctx context.Context, o *options, inv *inventory.Inventory) (*state.Snapshot, error) {
	cat, err := a.loadKEV(ctx, o)
	if err != nil {
		return nil, err
	}
	eng, err := fingerprint.Default()
	if err != nil {
		return nil, err
	}
	now := a.now()
	candidates := match.Run(inv, cat, eng, match.Options{Now: now})
	scores := a.loadEPSS(ctx, o, match.CVEs(candidates))
	fs := match.Run(inv, cat, eng, match.Options{Now: now, EPSS: scores})
	snap := &state.Snapshot{
		Organization: inv.Organization,
		GeneratedAt:  now.UTC(),
		KEVVersion:   cat.CatalogVersion,
		Findings:     fs,
	}
	for _, f := range fs {
		if s, ok := scores[f.CVE]; ok && s.Date > snap.EPSSDate {
			snap.EPSSDate = s.Date
		}
	}
	return snap, nil
}

// previous loads the last snapshot. first is true before the first run.
func previous(store state.Store) (prev []match.Finding, first bool, err error) {
	snap, err := store.LoadFindings()
	if errors.Is(err, state.ErrNoFindings) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return snap.Findings, false, nil
}

func meta(inv *inventory.Inventory, snap *state.Snapshot, lang string) report.Meta {
	m := report.Meta{
		Organization: snap.Organization,
		GeneratedAt:  snap.GeneratedAt,
		Lang:         lang,
		KEVVersion:   snap.KEVVersion,
		EPSSDate:     snap.EPSSDate,
	}
	if inv != nil {
		m.Assets, m.Services, m.Technologies = inv.Counts()
	}
	return m
}

func (a *app) cmdMatch(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("match", "[flags]", "Match the last inventory against the KEV catalog and save the findings.")
	o.stateFlags(fs)
	o.feedFlags(fs)
	o.langFlag(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	store := state.Store{Dir: o.stateDir}
	inv, err := store.LoadInventory()
	if err != nil {
		return err
	}
	prev, first, err := previous(store)
	if err != nil {
		return err
	}
	snap, err := a.matchInventory(ctx, o, inv)
	if err != nil {
		return err
	}
	if err := store.SaveFindings(snap); err != nil {
		return err
	}
	added, resolved := state.Diff(prev, snap.Findings)
	fmt.Fprint(a.stdout, report.Summary(snap.Findings, added, resolved, first, meta(inv, snap, o.lang)))
	return nil
}

func (a *app) cmdRun(ctx context.Context, args []string) (int, error) {
	o := &options{}
	fs := a.flags("run", "[-scope scope.json] [flags]",
		"Discover hosts, match them against known exploited flaws, write the fix list\nand send new findings to chat. Made to run from cron or a systemd timer.")
	o.scanFlags(fs)
	o.stateFlags(fs)
	o.feedFlags(fs)
	o.langFlag(fs)
	fs.StringVar(&o.webhook, "webhook", "", "Slack-compatible webhook for new findings (or set HEJNAL_WEBHOOK)")
	fs.StringVar(&o.failOn, "fail-on", "none", "exit with status 2 when new findings reach this severity: critical, high, medium, low or none")
	fs.StringVar(&o.out, "out", "", "where to write the fix list (default <state>/fixlist.md)")
	if err := a.parse(fs, args); err != nil {
		return exitError, err
	}
	if err := o.check(); err != nil {
		return exitError, err
	}
	failOn, err := match.ParseSeverity(o.failOn)
	if err != nil {
		return exitError, err
	}
	if o.webhook == "" {
		o.webhook = os.Getenv("HEJNAL_WEBHOOK")
	}
	hook := notify.Webhook{URL: o.webhook, Client: a.client, UserAgent: version.UserAgent()}
	if o.webhook != "" {
		if err := hook.Validate(); err != nil {
			return exitError, err
		}
	}
	if o.out == "" {
		o.out = filepath.Join(o.stateDir, "fixlist.md")
	}

	s, err := a.loadScope(o.scope)
	if err != nil {
		return exitError, err
	}
	a.printBanner(s)
	eng, err := fingerprint.Default()
	if err != nil {
		return exitError, err
	}
	inv, err := a.discover(ctx, s, eng, o)
	if err != nil {
		return exitError, err
	}
	store := state.Store{Dir: o.stateDir}
	if err := store.SaveInventory(inv); err != nil {
		return exitError, err
	}
	prev, first, err := previous(store)
	if err != nil {
		return exitError, err
	}
	snap, err := a.matchInventory(ctx, o, inv)
	if err != nil {
		return exitError, err
	}
	if err := store.SaveFindings(snap); err != nil {
		return exitError, err
	}
	added, resolved := state.Diff(prev, snap.Findings)
	m := meta(inv, snap, o.lang)

	var fix bytes.Buffer
	if err := report.FixList(&fix, snap.Findings, m); err != nil {
		return exitError, err
	}
	if err := state.WriteFile(o.out, fix.Bytes()); err != nil {
		return exitError, err
	}
	summary := report.Summary(snap.Findings, added, resolved, first, m)
	fmt.Fprint(a.stdout, summary)
	fmt.Fprintf(a.stdout, "Fix list written to %s.\n", o.out)

	if o.webhook != "" && (first || len(added) > 0) {
		if err := hook.Send(ctx, summary); err != nil {
			return exitError, err
		}
	}
	if match.AtLeast(added, failOn) {
		return exitFindings, nil
	}
	return exitOK, nil
}

func (a *app) cmdReport(args []string) error {
	kind := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		kind, args = args[0], args[1:]
	}
	o := &options{}
	fs := a.flags("report", "fixlist|nis2 [flags]",
		"Print a report from the last run:\n  fixlist  what to fix, most urgent first\n  nis2     a draft NIS2 early warning, for use if a system was compromised")
	o.stateFlags(fs)
	o.langFlag(fs)
	fs.StringVar(&o.out, "o", "", "write to this file instead of standard output")
	if kind == "" {
		// Allow flags before the report name.
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return err
			}
			return errUsage
		}
		if fs.NArg() > 0 {
			kind, args = fs.Arg(0), fs.Args()[1:]
		} else {
			args = nil
		}
	}
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	store := state.Store{Dir: o.stateDir}
	snap, err := store.LoadFindings()
	if err != nil {
		return err
	}
	inv, err := store.LoadInventory()
	if err != nil && !errors.Is(err, state.ErrNoInventory) {
		return err
	}
	m := meta(inv, snap, o.lang)
	var buf bytes.Buffer
	switch kind {
	case "fixlist":
		err = report.FixList(&buf, snap.Findings, m)
	case "nis2":
		err = report.NIS2(&buf, snap.Findings, m)
	case "":
		fs.Usage()
		return errUsage
	default:
		return fmt.Errorf("unknown report %q: use fixlist or nis2", kind)
	}
	if err != nil {
		return err
	}
	if o.out == "" {
		_, err = a.stdout.Write(buf.Bytes())
		return err
	}
	if err := state.WriteFile(o.out, buf.Bytes()); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Wrote %s.\n", o.out)
	return nil
}

func (a *app) cmdRules(args []string) error {
	fs := a.flags("rules", "", "List the products Hejnal recognises.")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	eng, err := fingerprint.Default()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPRODUCT\tCATEGORY\tADMIN")
	rules := eng.Rules()
	for _, r := range rules {
		admin := ""
		if r.Admin {
			admin = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Category, admin)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "\n%d products. Rules live in internal/fingerprint/rules.json.\n", len(rules))
	return nil
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}
