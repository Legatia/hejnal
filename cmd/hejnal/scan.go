package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	fs := a.flags("feeds", "[flags]", "Download CISA's Known Exploited Vulnerabilities catalog and ENISA's list of\nexploited vulnerabilities from the EUVD.")
	o.stateFlags(fs)
	o.cacheFlag(fs)
	fs.BoolVar(&o.noEUVD, "no-euvd", false, "do not download ENISA's list of exploited vulnerabilities")
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
	cisa, enisa, only := 0, 0, 0
	for _, v := range cat.Vulnerabilities {
		switch {
		case v.ENISAOnly:
			only++
		default:
			cisa++
		}
		if v.ENISA {
			enisa++
		}
	}
	fmt.Fprintf(a.stdout, "CISA KEV catalog %s: %d known exploited flaws.\n", cat.CatalogVersion, cisa)
	if cat.EUVDDate != "" {
		fmt.Fprintf(a.stdout, "ENISA EUVD list of %s: %d known exploited flaws, %d of them not in CISA's catalog.\n", cat.EUVDDate, enisa, only)
	}
	return nil
}

func (a *app) cmdMatch(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("match", "[flags]", "Match the last inventory against the lists of exploited flaws and save the findings.")
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
	fs.StringVar(&o.teams, "teams-webhook", "", "Microsoft Teams Workflows webhook for new findings (or set HEJNAL_TEAMS_WEBHOOK)")
	fs.StringVar(&o.emailTo, "email-to", "", "comma-separated addresses to email new findings to; SMTP settings come from HEJNAL_SMTP_* (or set HEJNAL_EMAIL_TO)")
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
	notifiers, err := a.notifiers(o)
	if err != nil {
		return exitError, err
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

	if len(notifiers) > 0 && (ch.First || len(ch.Added) > 0) {
		title, lines := report.SummaryLines(snap.Findings, ch.Added, ch.Resolved, ch.First, m)
		msg := notify.Message{Title: title, Lines: lines, FixList: fix.Bytes()}
		var errs []error
		for _, n := range notifiers {
			if err := n.Notify(ctx, msg); err != nil {
				errs = append(errs, err)
			}
		}
		if err := errors.Join(errs...); err != nil {
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

// notifiers builds the configured notification channels. Secrets come from
// the environment so they stay out of process lists and shell history.
func (a *app) notifiers(o *options) ([]notify.Notifier, error) {
	var out []notify.Notifier
	if o.webhook == "" {
		o.webhook = os.Getenv("HEJNAL_WEBHOOK")
	}
	if o.webhook != "" {
		w := notify.Webhook{URL: o.webhook, Client: a.client, UserAgent: version.UserAgent()}
		if err := w.Validate(); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	if o.teams == "" {
		o.teams = os.Getenv("HEJNAL_TEAMS_WEBHOOK")
	}
	if o.teams != "" {
		t := notify.Teams{URL: o.teams, Client: a.client, UserAgent: version.UserAgent()}
		if err := t.Validate(); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if o.emailTo == "" {
		o.emailTo = os.Getenv("HEJNAL_EMAIL_TO")
	}
	if o.emailTo != "" {
		e := notify.Email{
			Host:     os.Getenv("HEJNAL_SMTP_HOST"),
			Username: os.Getenv("HEJNAL_SMTP_USER"),
			Password: os.Getenv("HEJNAL_SMTP_PASSWORD"),
			From:     os.Getenv("HEJNAL_SMTP_FROM"),
		}
		if p := os.Getenv("HEJNAL_SMTP_PORT"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("HEJNAL_SMTP_PORT must be a port number")
			}
			e.Port = n
		}
		for _, to := range strings.Split(o.emailTo, ",") {
			if to = strings.TrimSpace(to); to != "" {
				e.To = append(e.To, to)
			}
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
