package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
)

func (a *app) cmdLive(ctx context.Context, args []string) (int, error) {
	o := &options{}
	fs := a.flags("live", "[flags] <url>...",
		"Check one system that is live, such as right after a deploy: what answers at\n"+
			"the address, its certificate, exposed admin pages and files, signs of a test\n"+
			"copy, and flaws attackers exploit in the products it runs.\n\n"+
			"Only the addresses named are contacted, and a host in the scope they\n"+
			"redirect to. Nothing is saved, so the record regular runs keep stays as it is.")
	fs.StringVar(&o.scope, "scope", "scope.json", "scope file; each address must be in it")
	fs.IntVar(&o.concurrency, "concurrency", 16, "parallel connections")
	fs.DurationVar(&o.timeout, "timeout", 8*time.Second, "timeout for each connection and response")
	wait := fs.Duration("wait", 0, "keep trying for this long, such as 2m, until the system answers")
	noChecks := fs.Bool("no-checks", false, "do not check fixed paths for exposed files (.git, .env, server-status) and product versions")
	fs.StringVar(&o.failOn, "fail-on", "high", "exit with status 2 when an item reaches this severity: critical, high, medium, low or none")
	item := fs.String("item", "", itemHelp)
	o.langFlag(fs)
	o.stateFlags(fs)
	o.feedFlags(fs)
	urls, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError, err
	}
	if err := o.check(); err != nil {
		return exitError, err
	}
	failOn, err := match.ParseSeverity(o.failOn)
	if err != nil {
		return exitError, err
	}
	if *wait < 0 {
		return exitError, errors.New("-wait cannot be negative")
	}
	if len(urls) == 0 {
		return exitError, errors.New("name the address to check, such as https://app.example.com")
	}
	if *item != "" && !engine.ValidItemID(*item) {
		return exitError, fmt.Errorf("-item %q is not an item's ID: the fix list and each issue show it, such as 30c07628", *item)
	}
	var targets []engine.LiveTarget
	for _, raw := range urls {
		t, err := engine.ParseLiveURL(raw)
		if err != nil {
			return exitError, err
		}
		if !slices.ContainsFunc(targets, func(o engine.LiveTarget) bool { return o.Host == t.Host && o.Port == t.Port }) {
			targets = append(targets, t)
		}
	}
	s, err := a.loadScope(o.scope)
	if err != nil {
		return exitError, err
	}
	// Refuse before anything is contacted, and say why: discovery would
	// leave such a target out without a word.
	for _, t := range targets {
		if err := t.Allowed(s, o.scope); err != nil {
			return exitError, err
		}
	}
	e, err := a.engine(o)
	if err != nil {
		return exitError, err
	}
	a.printBanner(s)
	for _, t := range targets {
		fmt.Fprintf(a.stderr, "Checking only %s.\n", t.Shown)
		if t.Path != "" {
			fmt.Fprintf(a.stderr, "Note: the check looks at the front page of %s and at fixed paths, not at %s.\n", t.Shown, t.Path)
		}
	}
	inv, problems, err := e.LookLive(ctx, s, targets, engine.LiveOptions{
		Checks: !*noChecks,
		Wait:   *wait,
		Pause:  a.livePause,
		Waiting: func(problems string) {
			fmt.Fprintf(a.stderr, "Waiting: %s.\n", problems)
		},
	})
	if err != nil {
		return exitError, err
	}
	if len(problems) > 0 {
		msg := "nothing to check: " + strings.Join(problems, "; ")
		if *wait > 0 {
			return exitError, fmt.Errorf("%s (waited %s)", msg, *wait)
		}
		return exitError, fmt.Errorf("%s; -wait 2m gives a deploy time to come up", msg)
	}
	snap, err := e.Assess(ctx, inv)
	if err != nil {
		return exitError, err
	}
	if *item != "" {
		known, err := engine.Known(state.Store{Dir: o.stateDir})
		if err != nil {
			return exitError, err
		}
		return a.printRecheck(engine.RecheckLive(*item, snap.Findings, known, targets, !*noChecks), o.lang)
	}
	open := match.Open(snap.Findings)
	a.printLive(a.stdout, inv, targets, snap.Findings, o.lang)
	if failOn != "" && match.AtLeast(open, failOn) {
		return exitFindings, nil
	}
	return exitOK, nil
}

// printLive writes what answered at each address and the items to fix.
func (a *app) printLive(w io.Writer, inv *inventory.Inventory, targets []engine.LiveTarget, fs []match.Finding, lang string) {
	named := map[*inventory.Service]bool{}
	for _, t := range targets {
		if _, svc := engine.LiveService(inv, t); svc != nil {
			named[svc] = true
			fmt.Fprintf(w, "Checked %s\n", t.Shown)
			printLiveService(w, svc)
		}
	}
	// What is left was reached through a redirect.
	for i := range inv.Assets {
		for j := range inv.Assets[i].Services {
			svc := &inv.Assets[i].Services[j]
			if named[svc] || svc.Status == 0 {
				continue
			}
			fmt.Fprintf(w, "Also checked %s, where a redirect leads\n", strings.TrimSuffix(svc.URL, "/"))
			printLiveService(w, svc)
		}
	}

	groups := match.Groups(match.Open(fs))
	if len(groups) == 0 {
		fmt.Fprintln(w, "Nothing found.")
	}
	for _, sev := range []match.Severity{match.Critical, match.High, match.Medium, match.Low} {
		first := true
		for _, g := range groups {
			if g.Severity != sev {
				continue
			}
			if first {
				fmt.Fprintf(w, "%s\n", strings.ToUpper(string(sev)))
				first = false
			}
			_, todo := report.ItemText(g, lang)
			fmt.Fprintf(w, "  %s\n", report.GroupTitle(g, lang))
			if todo != "" {
				fmt.Fprintf(w, "    → %s\n", stripMarkdown(todo))
			}
			if g.URL != "" {
				fmt.Fprintf(w, "    at %s\n", g.URL)
			}
			fmt.Fprintln(w)
		}
	}
	if n := len(match.Groups(match.Active(fs))) - len(groups); n > 0 {
		fmt.Fprintf(w, "Not listed: %s.\n", count(n, "accepted item", "accepted items"))
	}
}

// printLiveService describes one answer: its status and title, where a
// redirect on the same host ended, the products seen and the certificate.
func printLiveService(w io.Writer, svc *inventory.Service) {
	answer := strconv.Itoa(svc.Status)
	if svc.Title != "" {
		answer += fmt.Sprintf(" %q", svc.Title)
	}
	if svc.FinalURL != "" {
		answer += " at " + svc.FinalURL
	}
	fmt.Fprintf(w, "  Answer: %s\n", answer)
	if svc.Status >= 300 && svc.Status < 400 {
		fmt.Fprintln(w, "  It redirects elsewhere. A redirect is followed only to a host and port in the scope.")
	}
	var products []string
	for _, t := range svc.Technologies {
		p := t.Name
		if t.Version != "" {
			p += " " + t.Version
		}
		products = append(products, p)
	}
	if len(products) > 0 {
		fmt.Fprintf(w, "  Products: %s\n", strings.Join(products, ", "))
	}
	if svc.TLS != nil {
		fmt.Fprintf(w, "  Certificate: valid until %s\n", svc.TLS.NotAfter.UTC().Format("2006-01-02"))
	}
	fmt.Fprintln(w)
}

// itemHelp describes -item for the commands that can say whether one item
// is still found.
const itemHelp = "say only whether the item with this `ID` is still found: exit status 2 while it is, 0 once it is not, 1 when this check cannot tell"

// printRecheck says whether a fresh look still finds one item, and returns
// the exit status that says the same.
func (a *app) printRecheck(r engine.Recheck, lang string) (int, error) {
	switch r.Status {
	case engine.ItemFound:
		fmt.Fprintf(a.stdout, "Item %s is still found: %s\n", r.ID, report.GroupTitle(*r.Group, lang))
		if _, todo := report.ItemText(*r.Group, lang); todo != "" {
			fmt.Fprintf(a.stdout, "  → %s\n", stripMarkdown(todo))
		}
		for _, p := range report.Places(*r.Group) {
			fmt.Fprintf(a.stdout, "  at %s\n", p)
		}
		return exitFindings, nil
	case engine.ItemMoved:
		fmt.Fprintf(a.stdout, "Item %s is not fixed: it is now item %s, %s\n", r.ID, r.Now.ID(), report.GroupTitle(*r.Now, lang))
		if _, todo := report.ItemText(*r.Now, lang); todo != "" {
			fmt.Fprintf(a.stdout, "  → %s\n", stripMarkdown(todo))
		}
		for _, p := range report.Places(*r.Now) {
			fmt.Fprintf(a.stdout, "  at %s\n", p)
		}
		return exitFindings, nil
	case engine.ItemGone:
		fmt.Fprintf(a.stdout, "Item %s is no longer found: %s\n", r.ID, report.GroupTitle(*r.Group, lang))
		return exitOK, nil
	case engine.ItemNotFound:
		fmt.Fprintf(a.stdout, "Item %s is not found.\n", r.ID)
		fmt.Fprintln(a.stderr, "Note: no saved result lists this ID, so Hejnal cannot tell that the item was ever found here. Check the ID, and that the project or address is the one the item names.")
		return exitOK, nil
	}
	return exitError, fmt.Errorf("cannot tell whether item %s is still there: %s", r.ID, r.Why)
}
