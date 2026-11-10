// Package discover finds an organisation's internet-facing hosts and services
// inside its authorised scope and identifies the software they run.
//
// Every connection goes through one guard that checks the host, the address
// and the port against the scope, so nothing outside it is contacted: not
// through DNS answers, redirects or names found in certificates. Discovery
// sends one ordinary GET / per web service, over the other of HTTP and HTTPS
// too when the first fails, and follows redirects on the same host. For a
// product whose rule has a server check, such as Next.js's App Router, it
// asks for the page once more with the check's headers. It never logs in,
// guesses paths or sends attack payloads.
package discover

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/scope"
)

// Sources record how a host was found.
const (
	SourceHost     = "host"     // listed in the scope by name or address
	SourceDomain   = "domain"   // an authorised domain or its www name
	SourceCT       = "ct"       // certificate transparency logs
	SourceTLS      = "tls-san"  // a name in a certificate Hejnal was shown
	SourceRedirect = "redirect" // an in-scope host a service redirected to
	SourceRange    = "range"    // an address in an authorised IP range
	SourceDNS      = "dns"      // a name from the DNS provider's records
)

const (
	// maxRounds limits how many times names found in certificates and
	// redirects are fed back into discovery.
	maxRounds = 3
	// maxAddrsPerHost limits how many addresses of one name are tried, so a
	// DNS answer with thousands of records cannot stall a run.
	maxAddrsPerHost = 4
	// maxListedIPs limits how many addresses an asset lists in the inventory.
	maxListedIPs = 16
)

// ErrOutOfScope is returned when something tries to contact a host, address
// or port outside the authorised scope.
var ErrOutOfScope = errors.New("out of scope")

// Resolver looks up the addresses of a hostname. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// CTSource lists names seen in certificate transparency logs for a domain.
type CTSource interface {
	Subdomains(ctx context.Context, domain string) ([]string, error)
}

// Options configures a discovery run.
type Options struct {
	Scope  *scope.Scope
	Engine *fingerprint.Engine
	// Resolver defaults to the system resolver.
	Resolver Resolver
	// CT, when set, adds subdomains seen in certificate transparency logs.
	CT CTSource
	// Concurrency is the number of parallel lookups and connections.
	Concurrency int
	// Timeout applies to each DNS lookup, connection and response.
	Timeout   time.Duration
	UserAgent string
	// WebPorts are the only ports probed on hosts found under a domain rather
	// than listed explicitly. Defaults to scope.WebPorts.
	WebPorts []int
	// MaxHosts caps how many hosts one run looks at.
	MaxHosts int
	// Names are more names to look at, such as the records a DNS provider
	// holds. Names outside the scope are ignored, like any other.
	Names []string
	// Checks turns on the opt-in checks: a few more GET requests to fixed
	// paths, for exposed files and product versions.
	Checks bool
	// TiedOnly, for scopes made of proven domain names rather than a signed
	// authorisation of addresses: Hejnal sends HTTP requests, banner reads and
	// opt-in checks only to web services whose TLS certificate names a name
	// under one of the scope's domains. Other hosts get only the TLS handshake,
	// and their port 80 is not probed.
	//
	// It applies to every name, whether found under the scope's domains by
	// any source or listed as a host; addresses are unaffected. The handshake is on
	// port 443 with the name as SNI, which must be among WebPorts. A name is
	// tied when its certificate covers the name itself or any name under one
	// of the scope's domains, wildcards included; the certificate need not be
	// trusted, since a server that is not the scope owner's has no reason to
	// carry their names. An untied name is listed with a note saying so.
	TiedOnly bool
	Now      func() time.Time
	Logf     func(format string, args ...any)
}

type target struct {
	host   string
	source string
	ports  []int
}

type resolution struct {
	all     []netip.Addr
	allowed []netip.Addr
	err     error
}

type runner struct {
	opts Options
	s    *scope.Scope
	web  *webClient

	mu       sync.Mutex
	dns      map[string]resolution
	assets   map[string]*inventory.Asset
	queued   map[string]bool
	found    map[string]string // in-scope names from certificates and redirects
	excluded map[netip.Addr]bool
	cnames   map[string]string   // name → the name it points to
	scripts  map[string][]string // host|port → scripts its front page loads
	copies   []copyCandidate     // staging or test names to compare with the live site
	ties     map[string]tie      // under TiedOnly: name → what its certificate showed
	capped   bool
}

// Run discovers hosts and services in the scope and identifies their software.
func Run(ctx context.Context, opts Options) (*inventory.Inventory, error) {
	r, err := newRunner(opts)
	if err != nil {
		return nil, err
	}
	defer r.web.close()
	opts = r.opts
	s := opts.Scope

	r.resolveExclusions(ctx)

	var batch []target
	add := func(host, source string, ports []int) {
		if t, ok := r.enqueue(host, source, ports); ok {
			batch = append(batch, t)
		}
	}
	for _, h := range s.Hosts {
		add(h, SourceHost, s.Ports)
	}
	for _, d := range s.Domains {
		add(d, SourceDomain, opts.WebPorts)
		add("www."+d, SourceDomain, opts.WebPorts)
	}
	if opts.CT != nil {
		for _, d := range s.Domains {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			names, err := opts.CT.Subdomains(ctx, d)
			if err != nil {
				opts.Logf("certificate transparency lookup for %s failed (%v): names known only from certificates are left out of this run", d, err)
				continue
			}
			before := len(batch)
			for _, n := range names {
				add(n, SourceCT, opts.WebPorts)
			}
			opts.Logf("certificate transparency: %d more names under %s", len(batch)-before, d)
		}
	}
	for _, n := range opts.Names {
		add(n, SourceDNS, opts.WebPorts)
	}
	for _, a := range s.Addresses() {
		add(a.String(), SourceRange, s.Ports)
	}

	for round := 0; len(batch) > 0 && round < maxRounds; round++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.scan(ctx, batch)
		batch = nil
		for _, f := range r.takeFound() {
			add(f.name, f.source, opts.WebPorts)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.markCopies()
	inv := r.inventory()
	for _, d := range s.Domains {
		if m, ok := r.mailAuth(ctx, d); ok {
			inv.Mail = append(inv.Mail, m)
		}
	}
	return inv, nil
}

func newRunner(opts Options) (*runner, error) {
	if opts.Scope == nil || opts.Engine == nil {
		return nil, errors.New("discover: scope and engine are required")
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	if len(opts.WebPorts) == 0 {
		opts.WebPorts = scope.WebPorts
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 2000
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "hejnal"
	}

	r := &runner{
		opts:     opts,
		s:        opts.Scope,
		dns:      map[string]resolution{},
		assets:   map[string]*inventory.Asset{},
		queued:   map[string]bool{},
		found:    map[string]string{},
		excluded: map[netip.Addr]bool{},
		cnames:   map[string]string{},
		scripts:  map[string][]string{},
		ties:     map[string]tie{},
	}
	r.web = newWebClient(r)
	return r, nil
}

// resolveExclusions looks up the excluded hostnames once, so their machines
// stay excluded when they are reached under another name (a CNAME, for
// example) or through an address range.
func (r *runner) resolveExclusions(ctx context.Context) {
	for _, h := range r.s.ExcludedHosts() {
		ips, _ := r.resolveName(ctx, h)
		r.mu.Lock()
		for _, ip := range ips {
			r.excluded[scope.Canonical(ip)] = true
		}
		r.mu.Unlock()
	}
	if n := len(r.excluded); n > 0 {
		r.opts.Logf("excluding %d addresses that excluded hosts resolve to", n)
	}
}

// enqueue adds a host to the next batch unless it was seen before, is out of
// scope or the host limit is reached.
func (r *runner) enqueue(host, source string, ports []int) (target, bool) {
	host = normalizeHost(host)
	if host == "" || !r.s.HostInScope(host) {
		return target{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.queued[host] {
		return target{}, false
	}
	if len(r.queued) >= r.opts.MaxHosts {
		if !r.capped {
			r.opts.Logf("reached the limit of %d hosts; skipping the rest", r.opts.MaxHosts)
			r.capped = true
		}
		return target{}, false
	}
	r.queued[host] = true
	return target{host: host, source: source, ports: ports}, true
}

func (r *runner) scan(ctx context.Context, batch []target) {
	r.opts.Logf("resolving %d hosts", len(batch))
	parallel(r.opts.Concurrency, len(batch), func(i int) {
		if ctx.Err() == nil {
			r.resolve(ctx, batch[i])
		}
	})

	// Under TiedOnly, names learn from a TLS handshake whether Hejnal may
	// send them anything more.
	var tieHosts []string
	for _, t := range batch {
		if r.needsTie(t.host) && len(r.lookup(ctx, t.host).allowed) > 0 {
			tieHosts = append(tieHosts, t.host)
		}
	}
	if len(tieHosts) > 0 {
		r.opts.Logf("reading the certificates of %d names", len(tieHosts))
		parallel(r.opts.Concurrency, len(tieHosts), func(i int) {
			if ctx.Err() == nil {
				r.web.tie(ctx, tieHosts[i])
			}
		})
	}

	type job struct {
		t    target
		port int
	}
	var jobs []job
	hosts := 0
	for _, t := range batch {
		if len(r.lookup(ctx, t.host).allowed) == 0 {
			continue
		}
		if r.untied(t.host) {
			r.addUntied(t)
			continue
		}
		hosts++
		for _, p := range t.ports {
			if r.allowedPort(t.host, p) {
				jobs = append(jobs, job{t, p})
			}
		}
	}
	r.opts.Logf("checking %d ports on %d hosts", len(jobs), hosts)
	parallel(r.opts.Concurrency, len(jobs), func(i int) {
		if ctx.Err() != nil {
			return
		}
		j := jobs[i]
		if svc := r.web.probe(ctx, j.t.host, j.port); svc != nil {
			r.addService(j.t, *svc)
		}
	})
}

// resolve looks up a target and records it as an asset when it is worth
// reporting even without open services.
func (r *runner) resolve(ctx context.Context, t target) {
	res := r.lookup(ctx, t.host)
	if t.source == SourceRange {
		return // addresses in ranges are only reported when something answers
	}
	a := &inventory.Asset{Host: t.host, Source: t.source, IPs: addrStrings(res.all)}
	switch {
	case len(res.all) == 0:
		// Names from logs and certificates often point nowhere any more. Only
		// report names the scope lists directly.
		if !slices.Contains(r.s.Hosts, t.host) && !slices.Contains(r.s.Domains, t.host) {
			return
		}
		a.Errors = append(a.Errors, dnsError(res.err))
	case len(res.allowed) == 0:
		reason := "not contacted: resolves only to private or reserved addresses"
		if slices.ContainsFunc(res.all, r.excludedIP) {
			reason = "not contacted: shares an address with an excluded host or range"
		}
		a.Errors = append(a.Errors, reason)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.assets[t.host]; !ok {
		r.assets[t.host] = a
	}
}

// resolveName asks the resolver for a name. The name is passed fully
// qualified, so the machine's DNS search domains are never appended to it.
func (r *runner) resolveName(ctx context.Context, host string) ([]netip.Addr, error) {
	lctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	ips, err := r.opts.Resolver.LookupNetIP(lctx, "ip", host+".")
	var out []netip.Addr
	for _, ip := range ips {
		out = append(out, ip.WithZone("").Unmap())
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out), err
}

// lookup resolves host once and keeps the addresses Hejnal may contact. Every
// connection to the host uses these checked addresses, even if DNS answers
// change during the run.
func (r *runner) lookup(ctx context.Context, host string) resolution {
	r.mu.Lock()
	res, ok := r.dns[host]
	r.mu.Unlock()
	if ok {
		return res
	}
	if !r.s.HostInScope(host) {
		return resolution{} // never resolve, and so never contact, names outside the scope
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		res.all = []netip.Addr{ip.WithZone("").Unmap()}
	} else {
		res.all, res.err = r.resolveName(ctx, host)
		if len(res.all) > 0 {
			r.recordCNAME(ctx, host)
		}
	}
	for _, ip := range res.all {
		if len(res.allowed) == maxAddrsPerHost {
			break
		}
		if r.allowedIP(host, ip) {
			res.allowed = append(res.allowed, ip)
		}
	}
	if len(res.all) > maxListedIPs {
		res.all = res.all[:maxListedIPs]
	}
	r.mu.Lock()
	if prev, ok := r.dns[host]; ok {
		res = prev
	} else {
		r.dns[host] = res
	}
	r.mu.Unlock()
	return res
}

// excludedIP reports whether an address is excluded by the scope or belongs
// to an excluded hostname.
func (r *runner) excludedIP(ip netip.Addr) bool {
	c := scope.Canonical(ip)
	r.mu.Lock()
	excluded := r.excluded[c]
	r.mu.Unlock()
	return excluded || r.s.IPExcluded(c)
}

// allowedIP decides whether Hejnal may connect to ip on behalf of host.
func (r *runner) allowedIP(host string, ip netip.Addr) bool {
	if r.excludedIP(ip) {
		return false
	}
	c := scope.Canonical(ip)
	if r.s.IPInScope(c) {
		return true // an authorised address or range
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if r.s.Explicit(host) {
		// A host listed by name may point at private addresses (Hejnal can
		// run inside a network), but never at this machine, link-local
		// addresses such as cloud metadata services, or multicast.
		return !localOnly(c)
	}
	// A name found under an authorised domain: only public internet
	// addresses, so DNS pointing at private or shared address space never
	// turns into a scan of the network Hejnal runs in.
	return publicIP(c)
}

// allowedPort reports whether port may be contacted on host: the configured
// ports for hosts and ranges listed in the scope, web ports for names found
// under a domain.
func (r *runner) allowedPort(host string, port int) bool {
	if r.s.Explicit(host) {
		return slices.Contains(r.s.Ports, port)
	}
	return slices.Contains(r.opts.WebPorts, port)
}

func localOnly(ip netip.Addr) bool {
	return !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast()
}

var (
	special4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	global6  = netip.MustParsePrefix("2000::/3")
	special6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),     // protocol assignments: Teredo, benchmarking, ORCHID
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("2002::/16"),     // 6to4, which embeds IPv4 addresses
		netip.MustParsePrefix("3fff::/20"),     // documentation
	}
)

// publicIP reports whether a canonical address is an ordinary public
// internet address. IPv6 is limited to global unicast space without the
// blocks that embed IPv4 addresses or are reserved.
func publicIP(ip netip.Addr) bool {
	if ip.Is4() {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return false
		}
		for _, p := range special4 {
			if p.Contains(ip) {
				return false
			}
		}
		return true
	}
	if !global6.Contains(ip) {
		return false
	}
	for _, p := range special6 {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// noteName records an in-scope name seen in a certificate or redirect so the
// next round can look at it.
func (r *runner) noteName(name, source string) {
	n := normalizeHost(strings.TrimPrefix(strings.TrimSpace(name), "*."))
	if n == "" || !r.s.HostInScope(n) {
		return
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.found[n]; ok || r.queued[n] {
		return
	}
	if len(r.found)+len(r.queued) >= r.opts.MaxHosts {
		return
	}
	r.found[n] = source
}

type foundName struct{ name, source string }

func (r *runner) takeFound() []foundName {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]foundName, 0, len(r.found))
	for n, s := range r.found {
		out = append(out, foundName{n, s})
	}
	r.found = map[string]string{}
	slices.SortFunc(out, func(a, b foundName) int { return strings.Compare(a.name, b.name) })
	return out
}

// tie is what the TLS handshake on tiePort showed for a name under
// Options.TiedOnly.
type tie struct {
	tied  bool
	chain []*x509.Certificate // the certificates shown, leaf first
}

// needsTie reports whether host must be tied to the scope by its
// certificate before Hejnal sends it anything but a TLS handshake.
func (r *runner) needsTie(host string) bool {
	if !r.opts.TiedOnly {
		return false
	}
	_, err := netip.ParseAddr(host)
	return err != nil
}

// untied reports whether Hejnal may not contact host beyond the TLS
// handshake, because its certificate did not tie it to the scope or was
// not read yet.
func (r *runner) untied(host string) bool {
	if !r.needsTie(host) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.ties[host].tied
}

// certNames returns the names a certificate is for: its DNS names, or its
// subject's common name when it has none.
func certNames(c *x509.Certificate) []string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames
	}
	if c.Subject.CommonName != "" {
		return []string{c.Subject.CommonName}
	}
	return nil
}

// certTied reports whether a certificate ties host to the scope: it covers
// host itself, or names any name under one of the scope's domains, with
// wildcards. A certificate for *.example.com names example.com's names; one
// for *.com names none.
func (r *runner) certTied(host string, c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	if c.VerifyHostname(host) == nil {
		return true
	}
	for _, n := range certNames(c) {
		n = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(n), "."), "*.")
		for _, d := range r.s.Domains {
			if n == d || strings.HasSuffix(n, "."+d) {
				return true
			}
		}
	}
	return false
}

// listNames shows up to three names and how many more there are.
func listNames(names []string) string {
	shown := names[:min(len(names), 3)]
	s := strings.Join(shown, ", ")
	if len(names) > len(shown) {
		s += fmt.Sprintf(" and %d more", len(names)-len(shown))
	}
	return clipRecord(s)
}

// addUntied lists a name Hejnal did not contact beyond the TLS handshake
// under Options.TiedOnly, and why. A certificate that would count as a
// foreign host's on a contacted name is reported as one here too.
func (r *runner) addUntied(t target) {
	r.mu.Lock()
	chain := r.ties[t.host].chain
	r.mu.Unlock()
	var foreign *inventory.Service
	if names, ok := r.foreignHost(t.host, chain); ok {
		foreign = &inventory.Service{Port: tiePort, Scheme: "https", URL: (&url.URL{Scheme: "https", Host: hostPort(t.host, tiePort, "https"), Path: "/"}).String(),
			Exposures: []inventory.Exposure{{Kind: ExposureForeignHost, Path: "/", Evidence: foreignEvidence(names)}}}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.assets[t.host]
	if a == nil {
		a = &inventory.Asset{Host: t.host, Source: t.source, IPs: addrStrings(r.dns[t.host].all)}
		r.assets[t.host] = a
	}
	note := fmt.Sprintf("not contacted further: port %d showed no TLS certificate, so nothing ties the server to the scope's domains", tiePort)
	if len(chain) > 0 {
		note = "not contacted further: the name points at a server whose certificate names none of the scope's domains"
		if names := certNames(chain[0]); len(names) > 0 {
			note += "; it names " + listNames(names)
		}
	}
	a.Errors = append(a.Errors, note)
	if foreign != nil {
		a.Services = append(a.Services, *foreign)
	}
}

func (r *runner) addService(t target, svc inventory.Service) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.assets[t.host]
	if a == nil {
		a = &inventory.Asset{Host: t.host, Source: t.source, IPs: addrStrings(r.dns[t.host].all)}
		r.assets[t.host] = a
	}
	a.Services = append(a.Services, svc)
}

func (r *runner) inventory() *inventory.Inventory {
	r.mu.Lock()
	defer r.mu.Unlock()
	inv := &inventory.Inventory{
		Organization: r.s.Organization,
		GeneratedAt:  r.opts.Now().UTC(),
		Assets:       []inventory.Asset{},
	}
	for _, a := range r.assets {
		slices.SortFunc(a.Services, func(x, y inventory.Service) int { return cmp.Compare(x.Port, y.Port) })
		inv.Assets = append(inv.Assets, *a)
	}
	slices.SortFunc(inv.Assets, func(x, y inventory.Asset) int { return strings.Compare(x.Host, y.Host) })
	return inv
}

func dnsError(err error) string {
	var de *net.DNSError
	switch {
	case err == nil:
		return "does not resolve"
	case errors.As(err, &de) && de.IsNotFound:
		return "does not resolve (no such host)"
	case errors.As(err, &de) && de.IsTimeout:
		return "DNS lookup timed out"
	}
	return fmt.Sprintf("DNS lookup failed: %v", err)
}

func addrStrings(ips []netip.Addr) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return h
}

// parallel calls fn for 0..n-1 using up to workers goroutines.
func parallel(workers, n int, fn func(i int)) {
	if n == 0 {
		return
	}
	workers = min(workers, n)
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}
