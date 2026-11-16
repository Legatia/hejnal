package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
)

// defaultLivePause is the wait between two looks at a system that is not
// up yet.
const defaultLivePause = 5 * time.Second

// LiveTarget is one address to check on its own, such as right after a
// deploy.
type LiveTarget struct {
	// Shown is the address without its path: scheme, host and port.
	Shown string
	Host  string
	Port  int
	// Path is the path the address named, when it is not the front page.
	Path string
}

// ParseLiveURL reads an address such as "https://app.example.com" or
// "app.example.com:8443"; one without a scheme is taken as HTTPS.
func ParseLiveURL(arg string) (LiveTarget, error) {
	raw := strings.TrimSpace(arg)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		// The argument is not repeated: an address that does not parse may
		// hold a password.
		return LiveTarget{}, errors.New("an address to check is not one: give addresses such as https://app.example.com")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if u.User != nil {
		return LiveTarget{}, fmt.Errorf("the address for %s holds a user name or password: leave them out", host)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return LiveTarget{}, fmt.Errorf("%s://%s: only http and https addresses can be checked", u.Scheme, host)
	}
	t := LiveTarget{Host: host, Port: 443}
	if u.Scheme == "http" {
		t.Port = 80
	}
	t.Shown = u.Scheme + "://" + bracketed(host)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return LiveTarget{}, fmt.Errorf("%s: %q is not a port", host, p)
		}
		if n != t.Port {
			t.Shown = u.Scheme + "://" + net.JoinHostPort(host, p)
		}
		t.Port = n
	}
	if u.Path != "" && u.Path != "/" {
		t.Path = u.Path
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

// Allowed reports why the scope does not allow checking the target, by the
// rules a full run follows: the host must be in the scope, and the port
// must be one the scope lists for it. file names the scope file in the
// message; it may be empty.
func (t LiveTarget) Allowed(s *scope.Scope, file string) error {
	where := "the scope"
	if file != "" {
		where = "the scope file " + file
	}
	if !s.HostInScope(t.Host) {
		return fmt.Errorf("%s is not in %s, or is excluded there: Hejnal only checks systems the scope lists", t.Host, where)
	}
	if s.Explicit(t.Host) {
		if !slices.Contains(s.Ports, t.Port) {
			return fmt.Errorf("%s: port %d is not among the ports in %s (%s)", t.Shown, t.Port, where, joinInts(s.Ports))
		}
		return nil
	}
	if !slices.Contains(scope.WebPorts, t.Port) {
		return fmt.Errorf("%s: a name under a domain is checked on ports %s only; to check port %d, list %s under \"hosts\" in %s",
			t.Shown, joinInts(scope.WebPorts), t.Port, t.Host, where)
	}
	return nil
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

// LiveService returns what answered for a target: the asset of its host and
// the service on its port, either of which may be missing.
func LiveService(inv *inventory.Inventory, t LiveTarget) (*inventory.Asset, *inventory.Service) {
	for i := range inv.Assets {
		a := &inv.Assets[i]
		if a.Host != t.Host {
			continue
		}
		for j := range a.Services {
			if a.Services[j].Port == t.Port {
				return a, &a.Services[j]
			}
		}
		return a, nil
	}
	return nil, nil
}

// liveProblem says why a target cannot be checked yet, or "" when a website
// answered there. final reports that waiting will not change it.
func liveProblem(inv *inventory.Inventory, t LiveTarget) (problem string, final bool) {
	a, svc := LiveService(inv, t)
	switch {
	case a == nil:
		return "it could not be looked at", true
	case svc == nil && len(a.Errors) > 0:
		return a.Errors[0], strings.HasPrefix(a.Errors[0], "not contacted")
	case svc == nil:
		return fmt.Sprintf("nothing answered on port %d", t.Port), false
	case svc.Status == 0:
		return fmt.Sprintf("port %d is open, but no website answered there", t.Port), false
	case svc.Status >= 500:
		return fmt.Sprintf("it answered with status %d", svc.Status), false
	}
	return "", false
}

// liveProblems lists the targets that cannot be checked yet, one per line
// of text.
func liveProblems(inv *inventory.Inventory, targets []LiveTarget) (lines []string, final bool) {
	for _, t := range targets {
		if p, f := liveProblem(inv, t); p != "" {
			lines = append(lines, t.Shown+": "+p)
			final = final || f
		}
	}
	return lines, final
}

// LiveOptions say how LookLive looks.
type LiveOptions struct {
	// Checks also asks each system that answers for the fixed paths and
	// product versions of Config.Checks.
	Checks bool
	// Wait keeps trying for this long until every target answers.
	Wait time.Duration
	// Pause is the time between two tries; five seconds when it is zero.
	Pause time.Duration
	// Waiting, when set, hears why the targets cannot be checked yet, each
	// time the reason changes.
	Waiting func(problems string)
}

// LookLive looks at the targets and nothing else, as Look does, and returns
// what answered. The caller checks each target against the scope first:
// discovery leaves out a target the scope does not allow without a word.
//
// While a system is coming up, each try is one request for its front page;
// the fixed paths are asked for once, when it answers. problems lists the
// targets where no website answered in the end; the inventory is not worth
// assessing then.
func (e *Engine) LookLive(ctx context.Context, s *scope.Scope, targets []LiveTarget, o LiveOptions) (inv *inventory.Inventory, problems []string, err error) {
	var named []discover.Target
	for _, t := range targets {
		i := slices.IndexFunc(named, func(n discover.Target) bool { return n.Host == t.Host })
		if i < 0 {
			named = append(named, discover.Target{Host: t.Host})
			i = len(named) - 1
		}
		if !slices.Contains(named[i].Ports, t.Port) {
			named[i].Ports = append(named[i].Ports, t.Port)
		}
	}
	pause := o.Pause
	if pause <= 0 {
		pause = defaultLivePause
	}
	if o.Wait > 0 {
		started, last := time.Now(), ""
		for {
			inv, err := e.Look(ctx, s, named, false)
			if err != nil {
				return nil, nil, err
			}
			problems, final := liveProblems(inv, targets)
			if len(problems) == 0 || final {
				break
			}
			if time.Since(started)+pause > o.Wait {
				break
			}
			if now := strings.Join(problems, "; "); now != last {
				if o.Waiting != nil {
					o.Waiting(now)
				}
				last = now
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(pause):
			}
		}
	}
	if inv, err = e.Look(ctx, s, named, o.Checks); err != nil {
		return nil, nil, err
	}
	problems, _ = liveProblems(inv, targets)
	return inv, problems, nil
}

// Look reports what answers on the named systems right now, and nothing
// else in the scope: no other host, no certificate transparency logs, no
// mail records. With checks set it also asks for the fixed paths and
// product versions of Config.Checks. The scope's rules hold as in any run.
//
// Nothing is saved: the inventory and the record of systems stay as the
// last full run left them, so looking at one system does not make the
// others appear gone.
func (e *Engine) Look(ctx context.Context, s *scope.Scope, targets []discover.Target, checks bool) (*inventory.Inventory, error) {
	opts := e.discoverOptions(s)
	opts.Only = targets
	opts.Checks = checks
	// Discovery logs its progress through a scope; for a system or two
	// that says nothing, and a caller may look many times while waiting.
	opts.Logf = func(string, ...any) {}
	if len(targets) == 0 {
		// Without targets, discovery would run over the whole scope.
		return &inventory.Inventory{Organization: s.Organization, GeneratedAt: e.cfg.Now().UTC()}, nil
	}
	return discover.Run(ctx, opts)
}

// Assess matches what Look found against the lists of exploited flaws and
// the end-of-support dates, and marks the items people accepted. Leaked
// secrets and code scans kept in the state directory are left out, since
// they are not about these systems. Nothing is saved but the feed cache,
// so the fix list and what people were told stay as they are.
func (e *Engine) Assess(ctx context.Context, inv *inventory.Inventory) (*state.Snapshot, error) {
	cat, err := e.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	return e.snapshot(ctx, inv, cat, false)
}

// Checks reports whether the engine was set up with the opt-in checks for
// exposed files and product versions.
func (e *Engine) Checks() bool { return e.cfg.Checks }
