package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/notify"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/version"
)

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
	e, err := a.engine(o)
	if err != nil {
		return err
	}
	a.printBanner(s)
	inv, err := e.Discover(ctx, s)
	if err != nil {
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
	e, err := a.engine(o)
	if err != nil {
		return err
	}
	cat, err := e.RefreshCatalog(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "CISA KEV catalog %s: %d known exploited flaws.\n", cat.CatalogVersion, len(cat.Vulnerabilities))
	return nil
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
	e, err := a.engine(o)
	if err != nil {
		return err
	}
	inv, err := e.Store().LoadInventory()
	if err != nil {
		return err
	}
	snap, err := e.Match(ctx, inv)
	if err != nil {
		return err
	}
	ch, err := e.Changes(snap)
	if err != nil {
		return err
	}
	fmt.Fprint(a.stdout, report.Summary(snap.Findings, ch.Added, ch.Resolved, ch.First, engine.Meta(snap, o.lang)))
	return e.MarkReported(snap)
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
	e, err := a.engine(o)
	if err != nil {
		return exitError, err
	}
	a.printBanner(s)
	res, err := e.Run(ctx, s)
	if err != nil {
		return exitError, err
	}
	snap, ch := res.Snapshot, res.Changes
	m := engine.Meta(snap, o.lang)

	var fix bytes.Buffer
	if err := report.FixList(&fix, snap.Findings, m); err != nil {
		return exitError, err
	}
	if err := writeFile(o.out, fix.Bytes()); err != nil {
		return exitError, err
	}
	summary := report.Summary(snap.Findings, ch.Added, ch.Resolved, ch.First, m)
	fmt.Fprint(a.stdout, summary)
	fmt.Fprintf(a.stdout, "Fix list written to %s.\n", o.out)

	if o.webhook != "" && (ch.First || len(ch.Added) > 0) {
		if err := hook.Send(ctx, summary); err != nil {
			// Leave the last report as it was, so the next run reports
			// these findings again.
			return exitError, fmt.Errorf("%w; the next run will report these findings again", err)
		}
	}
	if err := e.MarkReported(snap); err != nil {
		return exitError, err
	}
	if match.AtLeast(ch.Added, failOn) {
		return exitFindings, nil
	}
	return exitOK, nil
}
