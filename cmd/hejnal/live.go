package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/scope"
)

// defaultLivePause is the wait between two looks at a system that is not
// up yet.
const defaultLivePause = 5 * time.Second

// liveTarget is one address named on the command line.
type liveTarget struct {
	// shown is the address without its path: scheme, host and port.
	shown string
	host  string
	port  int
	// path is the path the address named, when it is not the front page.
	path string
}

// parseLiveURL reads an address such as "https://app.example.com" or
// "app.example.com:8443"; one without a scheme is taken as HTTPS.
func parseLiveURL(arg string) (liveTarget, error) {
	raw := strings.TrimSpace(arg)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		// The argument is not repeated: an address that does not parse may
		// hold a password.
		return liveTarget{}, errors.New("an address to check is not one: give addresses such as https://app.example.com")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if u.User != nil {
		return liveTarget{}, fmt.Errorf("the address for %s holds a user name or password: leave them out", host)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return liveTarget{}, fmt.Errorf("%s://%s: only http and https addresses can be checked", u.Scheme, host)
	}
	t := liveTarget{host: host, port: 443}
	if u.Scheme == "http" {
		t.port = 80
	}
	t.shown = u.Scheme + "://" + bracketed(host)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return liveTarget{}, fmt.Errorf("%s: %q is not a port", host, p)
		}
		if n != t.port {
			t.shown = u.Scheme + "://" + net.JoinHostPort(host, p)
		}
		t.port = n
	}
	if u.Path != "" && u.Path != "/" {
		t.path = u.Path
	}
	return t, nil
}

// bracketed writes an IPv6 address the way a URL holds it.
func bracketed(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// liveScopeCheck reports why the scope does not allow checking a target,
// by the rules a full run follows: the host must be in the scope, and the
// port must be one the scope lists for it.
func liveScopeCheck(s *scope.Scope, file string, t liveTarget) error {
	if !s.HostInScope(t.host) {
		return fmt.Errorf("%s is not in the scope file %s, or is excluded there: Hejnal only checks systems the scope lists", t.host, file)
	}
	if s.Explicit(t.host) {
		if !slices.Contains(s.Ports, t.port) {
			return fmt.Errorf("%s: port %d is not among the ports in the scope file %s (%s)", t.shown, t.port, file, joinInts(s.Ports))
		}
		return nil
	}
	if !slices.Contains(scope.WebPorts, t.port) {
		return fmt.Errorf("%s: a name under a domain is checked on ports %s only; to check port %d, list %s under \"hosts\" in %s",
			t.shown, joinInts(scope.WebPorts), t.port, t.host, file)
	}
	return nil
}

// liveService returns what answered for a target: the asset of its host and
// the service on its port, either of which may be missing.
func liveService(inv *inventory.Inventory, t liveTarget) (*inventory.Asset, *inventory.Service) {
	for i := range inv.Assets {
		a := &inv.Assets[i]
		if a.Host != t.host {
			continue
		}
		for j := range a.Services {
			if a.Services[j].Port == t.port {
				return a, &a.Services[j]
			}
		}
		return a, nil
	}
	return nil, nil
}

// liveProblem says why a target cannot be checked yet, or "" when a website
// answered there. final reports that waiting will not change it.
func liveProblem(inv *inventory.Inventory, t liveTarget) (problem string, final bool) {
	a, svc := liveService(inv, t)
	switch {
	case a == nil:
		return "it could not be looked at", true
	case svc == nil && len(a.Errors) > 0:
		return a.Errors[0], strings.HasPrefix(a.Errors[0], "not contacted")
	case svc == nil:
		return fmt.Sprintf("nothing answered on port %d", t.port), false
	case svc.Status == 0:
		return fmt.Sprintf("port %d is open, but no website answered there", t.port), false
	case svc.Status >= 500:
		return fmt.Sprintf("it answered with status %d", svc.Status), false
	}
	return "", false
}

// liveProblems lists the targets that cannot be checked yet, one per line
// of text.
func liveProblems(inv *inventory.Inventory, targets []liveTarget) (lines []string, final bool) {
	for _, t := range targets {
		if p, f := liveProblem(inv, t); p != "" {
			lines = append(lines, t.shown+": "+p)
			final = final || f
		}
	}
	return lines, final
}

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
	var targets []liveTarget
	for _, raw := range urls {
		t, err := parseLiveURL(raw)
		if err != nil {
			return exitError, err
		}
		if !slices.ContainsFunc(targets, func(o liveTarget) bool { return o.host == t.host && o.port == t.port }) {
			targets = append(targets, t)
		}
	}
	s, err := a.loadScope(o.scope)
	if err != nil {
		return exitError, err
	}
	// Refuse before anything is contacted, and say why: discovery would
	// leave such a target out without a word.
	var named []discover.Target
	for _, t := range targets {
		if err := liveScopeCheck(s, o.scope, t); err != nil {
			return exitError, err
		}
		i := slices.IndexFunc(named, func(n discover.Target) bool { return n.Host == t.host })
		if i < 0 {
			named = append(named, discover.Target{Host: t.host})
			i = len(named) - 1
		}
		named[i].Ports = append(named[i].Ports, t.port)
	}
	e, err := a.engine(o)
	if err != nil {
		return exitError, err
	}
	a.printBanner(s)
	for _, t := range targets {
		fmt.Fprintf(a.stderr, "Checking only %s.\n", t.shown)
		if t.path != "" {
			fmt.Fprintf(a.stderr, "Note: the check looks at the front page of %s and at fixed paths, not at %s.\n", t.shown, t.path)
		}
	}

	// While the system is coming up, each try is one request for its front
	// page. The fixed paths are asked for once, when it answers.
	if *wait > 0 {
		started, last := time.Now(), ""
		for {
			inv, err := e.Look(ctx, s, named, false)
			if err != nil {
				return exitError, err
			}
			problems, final := liveProblems(inv, targets)
			if len(problems) == 0 || final {
				break
			}
			if time.Since(started)+a.livePause > *wait {
				break
			}
			if now := strings.Join(problems, "; "); now != last {
				fmt.Fprintf(a.stderr, "Waiting: %s.\n", now)
				last = now
			}
			select {
			case <-ctx.Done():
				return exitError, ctx.Err()
			case <-time.After(a.livePause):
			}
		}
	}
	inv, err := e.Look(ctx, s, named, !*noChecks)
	if err != nil {
		return exitError, err
	}
	if problems, _ := liveProblems(inv, targets); len(problems) > 0 {
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
	open := match.Open(snap.Findings)
	a.printLive(a.stdout, inv, targets, snap.Findings, o.lang)
	if failOn != "" && match.AtLeast(open, failOn) {
		return exitFindings, nil
	}
	return exitOK, nil
}

// printLive writes what answered at each address and the items to fix.
func (a *app) printLive(w io.Writer, inv *inventory.Inventory, targets []liveTarget, fs []match.Finding, lang string) {
	named := map[*inventory.Service]bool{}
	for _, t := range targets {
		if _, svc := liveService(inv, t); svc != nil {
			named[svc] = true
			fmt.Fprintf(w, "Checked %s\n", t.shown)
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
