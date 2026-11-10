// Package scope loads and enforces the list of systems an organisation has
// authorised Hejnal to check. Nothing outside the scope is ever contacted.
package scope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DefaultPorts are probed on hosts and IP ranges listed explicitly in the scope.
var DefaultPorts = []int{80, 443, 8080, 8443}

// WebPorts are the only ports probed on hostnames discovered under an
// authorised domain (for example through certificate transparency). They are
// the same ports a browser uses, so discovery never port-scans machines that
// may sit on shared or third-party infrastructure.
var WebPorts = []int{80, 443}

// MaxAddresses caps how many IP addresses the authorised ranges may expand to,
// so a typo in a range cannot turn into a large scan.
const MaxAddresses = 1024

// Authorization records who confirmed that the organisation owns, or has
// written permission to test, every system in the scope.
type Authorization struct {
	ConfirmedBy string `json:"confirmedBy"`
	Date        string `json:"date"`
	Statement   string `json:"statement"`
}

// Scope is the authorised target list for one organisation.
type Scope struct {
	Organization  string        `json:"organization"`
	Authorization Authorization `json:"authorization"`
	// Domains authorise the domain itself and every subdomain under it.
	Domains []string `json:"domains,omitempty"`
	// Hosts authorise single hostnames or IP addresses. They are probed on all
	// configured ports.
	Hosts []string `json:"hosts,omitempty"`
	// CIDRs authorise IP ranges. They are probed on all configured ports.
	CIDRs []string `json:"cidrs,omitempty"`
	// Exclude removes hostnames (and their subdomains), IPs or ranges.
	Exclude []string `json:"exclude,omitempty"`
	// Ports probed on explicit hosts and ranges. Defaults to DefaultPorts.
	Ports []int `json:"ports,omitempty"`

	prefixes        []netip.Prefix
	hostIPs         []netip.Addr
	excludeHosts    []string
	excludePrefixes []netip.Prefix
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Load reads and validates a scope file. Unknown fields are rejected so a
// misspelt key cannot silently widen or narrow the scope.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, time.Now())
}

// Parse decodes and validates a scope document.
func Parse(data []byte, now time.Time) (*Scope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Scope
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if err := s.Validate(now); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks the scope and prepares it for lookups.
func (s *Scope) Validate(now time.Time) error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf("scope: "+format, args...)) }

	s.Organization = strings.TrimSpace(s.Organization)
	if s.Organization == "" {
		add("organization is required")
	}
	a := &s.Authorization
	a.ConfirmedBy = strings.TrimSpace(a.ConfirmedBy)
	a.Statement = strings.TrimSpace(a.Statement)
	if a.ConfirmedBy == "" {
		add("authorization.confirmedBy is required: name the person who confirmed you may test these systems")
	}
	if a.Statement == "" {
		add("authorization.statement is required")
	}
	if d, err := time.Parse("2006-01-02", strings.TrimSpace(a.Date)); err != nil {
		add("authorization.date must be YYYY-MM-DD")
	} else if d.After(now.Add(24 * time.Hour)) {
		add("authorization.date %s is in the future", a.Date)
	}

	if len(s.Domains)+len(s.Hosts)+len(s.CIDRs) == 0 {
		add("add at least one domain, host or IP range")
	}

	for i, d := range s.Domains {
		n := normalizeHost(d)
		if _, err := netip.ParseAddr(n); err == nil {
			add("domain %q is an IP address; put it under hosts", d)
			continue
		}
		if err := validHostname(n); err != nil {
			add("domain %q: %v", d, err)
			continue
		}
		if !strings.Contains(n, ".") {
			add("domain %q must include a dot", d)
			continue
		}
		s.Domains[i] = n
	}

	s.hostIPs = nil
	for i, h := range s.Hosts {
		n := normalizeHost(h)
		if ip, err := netip.ParseAddr(n); err == nil {
			if ip.Zone() != "" {
				add("host %q: IPv6 zones are not supported", h)
				continue
			}
			ip = Canonical(ip)
			s.Hosts[i] = ip.String()
			s.hostIPs = append(s.hostIPs, ip)
			continue
		}
		if err := validHostname(n); err != nil {
			add("host %q: %v", h, err)
			continue
		}
		s.Hosts[i] = n
	}

	s.prefixes = nil
	total := new(big.Int)
	for _, c := range s.CIDRs {
		p, err := parsePrefix(c)
		if err != nil {
			add("cidr %q: %v", c, err)
			continue
		}
		total.Add(total, prefixSize(p))
		s.prefixes = append(s.prefixes, p)
	}
	if total.Cmp(big.NewInt(MaxAddresses)) > 0 {
		add("IP ranges expand to %s addresses; the limit is %d, split the scope or narrow the ranges", total, MaxAddresses)
	}

	s.excludeHosts, s.excludePrefixes = nil, nil
	for _, e := range s.Exclude {
		n := normalizeHost(e)
		if _, err := netip.ParseAddr(n); err == nil || strings.ContainsAny(n, "/:") {
			p, err := parsePrefix(n)
			if err != nil {
				add("exclude %q: %v", e, err)
				continue
			}
			s.excludePrefixes = append(s.excludePrefixes, p)
			continue
		}
		if err := validHostname(n); err != nil {
			add("exclude %q: %v", e, err)
			continue
		}
		s.excludeHosts = append(s.excludeHosts, n)
	}

	if len(s.Ports) == 0 {
		s.Ports = slices.Clone(DefaultPorts)
	}
	for _, p := range s.Ports {
		if p < 1 || p > 65535 {
			add("port %d is out of range", p)
		}
	}
	slices.Sort(s.Ports)
	s.Ports = slices.Compact(s.Ports)

	return errors.Join(errs...)
}

// HostInScope reports whether a hostname or IP literal may be contacted.
// Hostnames must be plain ASCII names; anything a resolver might interpret
// differently from this check, such as Unicode look-alikes or empty labels,
// is out of scope.
func (s *Scope) HostInScope(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.Zone() == "" && s.IPInScope(ip)
	}
	if validHostname(h) != nil {
		return false
	}
	if s.hostExcluded(h) {
		return false
	}
	if slices.Contains(s.Hosts, h) {
		return true
	}
	for _, d := range s.Domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// IPInScope reports whether an IP address is listed as a host or inside an
// authorised range, and not excluded.
func (s *Scope) IPInScope(ip netip.Addr) bool {
	ip = Canonical(ip)
	if s.IPExcluded(ip) {
		return false
	}
	if slices.Contains(s.hostIPs, ip) {
		return true
	}
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// IPExcluded reports whether an address falls in an excluded address or range.
// Hostnames that resolve to an excluded address are never contacted.
func (s *Scope) IPExcluded(ip netip.Addr) bool {
	ip = Canonical(ip)
	for _, p := range s.excludePrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// nat64 is the well-known NAT64 prefix (RFC 6052). On IPv6-only networks,
// DNS64 resolvers synthesise addresses in it that a gateway translates to the
// embedded IPv4 address.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Canonical returns the address a connection to ip actually reaches, for
// scope checks: without a zone, IPv4-mapped IPv6 as IPv4, and NAT64
// addresses as the IPv4 address they translate to.
func Canonical(ip netip.Addr) netip.Addr {
	ip = ip.WithZone("").Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return ip
}

// ExcludedHosts returns the hostnames listed under exclude.
func (s *Scope) ExcludedHosts() []string { return slices.Clone(s.excludeHosts) }

// Explicit reports whether a host was listed by name or address, which
// allows probing all configured ports rather than only web ports.
func (s *Scope) Explicit(host string) bool {
	h := normalizeHost(host)
	if slices.Contains(s.Hosts, h) {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return s.IPInScope(ip)
	}
	return false
}

// Addresses expands the authorised ranges into individual addresses,
// skipping excluded ones.
func (s *Scope) Addresses() []netip.Addr {
	var out []netip.Addr
	for _, p := range s.prefixes {
		for a := p.Masked().Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
			if s.IPInScope(a) {
				out = append(out, a)
			}
		}
	}
	return out
}

func (s *Scope) hostExcluded(h string) bool {
	for _, e := range s.excludeHosts {
		if h == e || strings.HasSuffix(h, "."+e) {
			return true
		}
	}
	return false
}

// exampleDomains are the names reserved for documentation. They are real
// hosts on the internet that belong to IANA, not to the person running
// Hejnal.
var exampleDomains = []string{"example.com", "example.net", "example.org"}

// exampleRanges are the address ranges reserved for documentation.
var exampleRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// Placeholders lists what a validated scope still carries from the example
// file: documentation names and ranges to check, and the example's
// organisation and authorisation. A scope with any of them was not written
// for the systems it would check, so Hejnal does not run it.
func (s *Scope) Placeholders() []string {
	var out []string
	ex := Example(time.Time{})
	if s.Organization == ex.Organization {
		out = append(out, fmt.Sprintf("organization %q", s.Organization))
	}
	if s.Authorization.ConfirmedBy == ex.Authorization.ConfirmedBy {
		out = append(out, fmt.Sprintf("authorization.confirmedBy %q", s.Authorization.ConfirmedBy))
	}
	reserved := func(h string) bool {
		if ip, err := netip.ParseAddr(h); err == nil {
			return slices.ContainsFunc(exampleRanges, func(p netip.Prefix) bool { return p.Contains(ip.Unmap()) })
		}
		return slices.ContainsFunc(exampleDomains, func(d string) bool { return h == d || strings.HasSuffix(h, "."+d) })
	}
	for _, d := range s.Domains {
		if reserved(d) {
			out = append(out, "domain "+d)
		}
	}
	for _, h := range s.Hosts {
		if reserved(h) {
			out = append(out, "host "+h)
		}
	}
	for _, p := range s.prefixes {
		if slices.ContainsFunc(exampleRanges, func(r netip.Prefix) bool { return r.Overlaps(p) }) {
			out = append(out, "range "+p.String())
		}
	}
	return out
}

// Example returns a template scope for `hejnal init`.
func Example(now time.Time) *Scope {
	return &Scope{
		Organization: "Example Sp. z o.o.",
		Authorization: Authorization{
			ConfirmedBy: "Jan Kowalski, IT manager",
			Date:        now.Format("2006-01-02"),
			Statement:   "We own these systems or have written permission from their owner to test them.",
		},
		Domains: []string{"example.com"},
		Hosts:   []string{"vpn.example.com"},
		CIDRs:   []string{"203.0.113.0/29"},
		Exclude: []string{"legacy.example.com"},
		Ports:   slices.Clone(DefaultPorts),
	}
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return h
}

func validHostname(h string) error {
	if h == "" {
		return errors.New("empty")
	}
	if strings.Contains(h, "*") {
		return errors.New("wildcards are not allowed; list the domain and Hejnal covers its subdomains")
	}
	if len(h) > 253 {
		return errors.New("too long")
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return fmt.Errorf("invalid label %q", l)
		}
	}
	// No top-level domain is all digits, and resolvers may read names such
	// as "8.0.1" as IPv4 addresses.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("looks like an IP address, not a name")
	}
	return nil
}

func parsePrefix(c string) (netip.Prefix, error) {
	c = strings.TrimSpace(c)
	if !strings.Contains(c, "/") {
		ip, err := netip.ParseAddr(c)
		if err != nil {
			return netip.Prefix{}, err
		}
		if ip.Zone() != "" {
			return netip.Prefix{}, errors.New("IPv6 zones are not supported")
		}
		ip = Canonical(ip)
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, err := netip.ParsePrefix(c)
	if err != nil {
		return netip.Prefix{}, err
	}
	p = p.Masked()
	// Ranges written as IPv4-mapped or NAT64 IPv6 cover IPv4 addresses.
	for _, embed := range []netip.Prefix{netip.MustParsePrefix("::ffff:0:0/96"), nat64} {
		if !p.Overlaps(embed) {
			continue
		}
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("ranges inside %s must be /96 or longer", embed)
		}
		return netip.PrefixFrom(Canonical(p.Addr()), p.Bits()-96).Masked(), nil
	}
	return p, nil
}

func prefixSize(p netip.Prefix) *big.Int {
	host := p.Addr().BitLen() - p.Bits()
	return new(big.Int).Lsh(big.NewInt(1), uint(host))
}
