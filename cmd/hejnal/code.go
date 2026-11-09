package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

const codeUsage = `Usage:
  hejnal code scan [flags] [<directory>...] [-image image.tar]...

  scan   check a project's dependencies, secrets and infrastructure code,
         and container images, for what attackers exploit

Run it in CI: only package names and versions leave the machine, to OSV
(osv.dev) and, as CVE IDs, to FIRST's EPSS API. With -upload, the results,
never the code, go to Hejnal Cloud.
`

func (a *app) cmdCode(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, codeUsage)
		return exitError, errUsage
	}
	switch args[0] {
	case "scan":
		return a.cmdCodeScan(ctx, args[1:])
	case "-h", "-help", "--help", "help":
		fmt.Fprint(a.stdout, codeUsage)
		return exitOK, nil
	}
	fmt.Fprintf(a.stderr, "hejnal code: unknown command %q\n\n%s", args[0], codeUsage)
	return exitError, errUsage
}

// listFlag collects a flag given several times.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func (a *app) cmdCodeScan(ctx context.Context, args []string) (int, error) {
	o := &options{}
	fs := a.flags("code scan", "[flags] [<directory>...]",
		"Check source directories and container images for vulnerable dependencies,\n"+
			"secrets and infrastructure settings that open a way in. Dependencies with\n"+
			"flaws attackers exploit come first; the many advisories nobody exploits\n"+
			"stay in a quiet list.")
	var images listFlag
	fs.Var(&images, "image", "also check this container image, saved with `docker save` or as an OCI layout (repeatable)")
	project := fs.String("project", "", "name for the project in reports and on Hejnal Cloud (default: the directory's name)")
	format := fs.String("format", "text", "output: text, json or sarif")
	out := fs.String("out", "", "write the output to this file instead of standard output")
	all := fs.Bool("all", false, "with -format text, also list the low items one by one")
	history := fs.Bool("history", false, "also scan every commit in the Git history for secrets")
	noDeps := fs.Bool("no-deps", false, "do not check dependencies")
	noSecrets := fs.Bool("no-secrets", false, "do not look for secrets")
	noIaC := fs.Bool("no-iac", false, "do not check infrastructure code")
	save := fs.Bool("save", false, "keep the result in the state directory, so the fix list and notifications of later runs include it")
	upload := fs.String("upload", "", "send the results to this Hejnal Cloud address, with the token in HEJNAL_UPLOAD_TOKEN")
	fs.StringVar(&o.failOn, "fail-on", "high", "exit with status 2 when an item reaches this severity: critical, high, medium, low or none")
	o.langFlag(fs)
	o.stateFlags(fs)
	o.feedFlags(fs)
	dirs, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError, err
	}
	if err := o.check(); err != nil {
		return exitError, err
	}
	if len(dirs) == 0 && len(images) == 0 {
		dirs = []string{"."}
	}
	failOn, err := match.ParseSeverity(o.failOn)
	if err != nil {
		return exitError, err
	}
	if *format != "text" && *format != "json" && *format != "sarif" {
		return exitError, fmt.Errorf("unknown format %q: use text, json or sarif", *format)
	}
	for _, d := range dirs {
		if st, err := os.Stat(d); err != nil {
			return exitError, err
		} else if !st.IsDir() {
			return exitError, fmt.Errorf("%s is not a directory; to check an image, use -image", d)
		}
	}
	token := os.Getenv("HEJNAL_UPLOAD_TOKEN")
	if *upload != "" {
		if err := uploadURLOK(*upload); err != nil {
			return exitError, err
		}
		if token == "" {
			return exitError, errors.New("-upload needs the organisation's upload token in HEJNAL_UPLOAD_TOKEN")
		}
	}
	name := *project
	if name == "" {
		if len(dirs) > 0 {
			abs, _ := filepath.Abs(dirs[0])
			name = filepath.Base(abs)
		} else {
			name = strings.TrimSuffix(filepath.Base(images[0]), filepath.Ext(images[0]))
		}
	}
	if o.cacheDir == "" {
		o.cacheDir = filepath.Join(o.stateDir, "cache")
	}
	e, err := a.engine(o)
	if err != nil {
		return exitError, err
	}
	req := engine.CodeRequest{Project: name, Dirs: dirs, Images: images, History: *history}
	if *noDeps {
		req.Skip = append(req.Skip, engine.PartDeps)
	}
	if *noSecrets {
		req.Skip = append(req.Skip, engine.PartSecrets)
	}
	if *noIaC {
		req.Skip = append(req.Skip, engine.PartIaC)
	}
	store := state.Store{Dir: o.stateDir}
	if *save && !*noSecrets {
		if req.FingerprintKey, err = store.LeakKey(); err != nil {
			return exitError, err
		}
	}
	scan, err := e.ScanCode(ctx, req)
	if err != nil {
		return exitError, err
	}

	var w io.Writer = a.stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return exitError, err
		}
		defer f.Close()
		w = f
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(scan)
	case "sarif":
		err = report.SARIF(w, scan.Findings, version.Version, o.lang)
	default:
		err = a.printCodeScan(w, scan, o.lang, *all)
	}
	if err != nil {
		return exitError, err
	}
	if *out != "" && *format != "text" {
		// The file is for tools; the log still says what was found.
		if err := a.printCodeScan(a.stdout, scan, o.lang, false); err != nil {
			return exitError, err
		}
	}
	for _, n := range scan.Notes {
		fmt.Fprintln(a.stderr, "Note:", n)
	}
	if *save {
		if err := store.SaveCodeScan(scan); err != nil {
			return exitError, err
		}
		fmt.Fprintf(a.stderr, "Saved to %s; the next run includes it.\n", filepath.Join(o.stateDir, state.CodeDir, state.ProjectFile(name)))
	}
	if *upload != "" {
		if err := a.uploadCodeScan(ctx, *upload, token, scan); err != nil {
			return exitError, err
		}
		fmt.Fprintf(a.stderr, "Sent the results for %s to Hejnal Cloud.\n", name)
	}
	if failOn != "" && match.AtLeast(match.Open(scan.Findings), failOn) {
		return exitFindings, nil
	}
	return exitOK, nil
}

func (a *app) printCodeScan(w io.Writer, scan *state.CodeScan, lang string, all bool) error {
	checked := []string{}
	if scan.Packages > 0 {
		checked = append(checked, fmt.Sprintf("%d packages", scan.Packages))
	}
	for _, p := range scan.Parts {
		if p != engine.PartDeps && p != engine.PartImages {
			checked = append(checked, p)
		}
	}
	if len(scan.Images) > 0 {
		checked = append(checked, "image "+strings.Join(scan.Images, ", "))
	}
	fmt.Fprintf(w, "Checked %s: %s.\n\n", scan.Project, strings.Join(checked, ", "))
	groups := match.Groups(match.Open(scan.Findings))
	if len(groups) == 0 {
		fmt.Fprintln(w, "Nothing found.")
		return nil
	}
	var low []match.Group
	for _, sev := range []match.Severity{match.Critical, match.High, match.Medium} {
		first := true
		for _, g := range groups {
			if g.Severity != sev {
				continue
			}
			if first {
				fmt.Fprintf(w, "%s\n", strings.ToUpper(string(sev)))
				first = false
			}
			a.printCodeItem(w, g, lang)
		}
	}
	for _, g := range groups {
		if g.Severity == match.Low {
			low = append(low, g)
		}
	}
	if len(low) > 0 {
		if all {
			fmt.Fprintln(w, "LOW")
			for _, g := range low {
				a.printCodeItem(w, g, lang)
			}
		} else {
			fmt.Fprintf(w, "Low: %d more items, such as advisories nobody is known to exploit. Add -all to list them.\n", len(low))
		}
	}
	return nil
}

func (a *app) printCodeItem(w io.Writer, g match.Group, lang string) {
	_, todo := report.ItemText(g, lang)
	fmt.Fprintf(w, "  %s\n", report.GroupTitle(g, lang))
	if todo != "" {
		fmt.Fprintf(w, "    → %s\n", stripMarkdown(todo))
	}
	f := g.Findings[0]
	if f.File != "" {
		where := f.File
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "    at %s\n", where)
	}
	fmt.Fprintln(w)
}

func stripMarkdown(s string) string { return strings.NewReplacer("`", "", "**", "").Replace(s) }

// uploadURLOK accepts HTTPS addresses, and plain HTTP only on this machine.
func uploadURLOK(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("-upload: %q is not an address", raw)
	}
	h := u.Hostname()
	if u.Scheme == "https" || u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1") {
		return nil
	}
	return errors.New("-upload needs an https:// address")
}

func (a *app) uploadCodeScan(ctx context.Context, base, token string, scan *state.CodeScan) error {
	body, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/api/v1/code-results", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("upload: Hejnal Cloud answered %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
