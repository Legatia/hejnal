package scope

import (
	"net/netip"
	"regexp"
	"strings"
)

// Owner names who looks after some of the systems in the scope, so each
// item to fix can go to the right person or team.
type Owner struct {
	// Name is the person or team, as the reports should show it.
	Name string `json:"name,omitempty"`
	// GitHub is the GitHub login that issues for these systems are
	// assigned to.
	GitHub string `json:"github,omitempty"`
	// Systems are hostnames (each covers its subdomains too), IP addresses
	// or IP ranges.
	Systems []string `json:"systems"`

	hosts    []string
	prefixes []netip.Prefix
}

// Label is how the owner is shown: the name, or the GitHub login when no
// name is set.
func (o Owner) Label() string {
	if o.Name != "" {
		return o.Name
	}
	return "@" + o.GitHub
}

// loginRE matches a GitHub login: letters, digits and single hyphens, up to
// 39 characters.
var loginRE = regexp.MustCompile(`^[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38}$`)

// maxOwnerName keeps an owner's name to one short line.
const maxOwnerName = 80

// validateOwners checks the owners and prepares them for lookups.
func (s *Scope) validateOwners(add func(format string, args ...any)) {
	for i := range s.Owners {
		o := &s.Owners[i]
		o.Name = strings.TrimSpace(o.Name)
		o.GitHub = strings.TrimPrefix(strings.TrimSpace(o.GitHub), "@")
		o.hosts, o.prefixes = nil, nil
		who := o.Name
		if who == "" {
			who = o.GitHub
		}
		switch {
		case who == "":
			add("owners[%d] needs a name or a github login", i)
			continue
		case len([]rune(o.Name)) > maxOwnerName || strings.ContainsAny(o.Name, "\r\n\t"):
			add("owner %q: the name must be one line of at most %d characters", who, maxOwnerName)
		}
		if o.GitHub != "" && !loginRE.MatchString(o.GitHub) {
			add("owner %q: %q is not a GitHub login", who, o.GitHub)
		}
		if len(o.Systems) == 0 {
			add("owner %q: list the systems they look after: hostnames, IP addresses or ranges", who)
		}
		for _, sys := range o.Systems {
			n := normalizeHost(sys)
			if _, err := netip.ParseAddr(n); err == nil || strings.ContainsAny(n, "/:") {
				p, err := parsePrefix(n)
				if err != nil {
					add("owner %q: system %q: %v", who, sys, err)
					continue
				}
				o.prefixes = append(o.prefixes, p)
				continue
			}
			if err := validHostname(n); err != nil {
				add("owner %q: system %q: %v", who, sys, err)
				continue
			}
			o.hosts = append(o.hosts, n)
		}
	}
}

// OwnerOf returns who looks after a host: the owner whose entry fits it
// most closely (the longest name, or the smallest range), and the first
// such owner when two fit equally. It returns nil when no owner lists the
// host.
func (s *Scope) OwnerOf(host string) *Owner {
	h := normalizeHost(host)
	if h == "" {
		return nil
	}
	var best *Owner
	score := -1
	if ip, err := netip.ParseAddr(h); err == nil {
		ip = Canonical(ip)
		for i := range s.Owners {
			for _, p := range s.Owners[i].prefixes {
				if p.Contains(ip) && p.Bits() > score {
					best, score = &s.Owners[i], p.Bits()
				}
			}
		}
		return best
	}
	for i := range s.Owners {
		for _, name := range s.Owners[i].hosts {
			if (h == name || strings.HasSuffix(h, "."+name)) && len(name) > score {
				best, score = &s.Owners[i], len(name)
			}
		}
	}
	return best
}
