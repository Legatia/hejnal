package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/inventory"
)

const (
	maxBody      = 512 << 10
	maxRedirects = 5
	bannerWait   = 2 * time.Second
	maxSANs      = 50
	// probeBudget, times the timeout, bounds one port check end to end;
	// checksBudget is added when the opt-in checks are on.
	probeBudget  = 5
	checksBudget = 4
)

// tlsHint matches the error pages servers send when plain HTTP reaches a TLS
// port, so Hejnal retries the port over HTTPS.
var tlsHint = regexp.MustCompile(`(?i)plain HTTP request was sent to HTTPS port|HTTP request to an HTTPS server|speaking plain HTTP to an SSL-enabled server|requires TLS`)

type webClient struct {
	r         *runner
	transport *http.Transport
}

func newWebClient(r *runner) *webClient {
	w := &webClient{r: r}
	w.transport = &http.Transport{
		// Connect directly: the point is to see what the target itself serves.
		Proxy:       nil,
		DialContext: w.dial,
		TLSClientConfig: &tls.Config{
			// Fingerprinting has to work with appliances that use self-signed or
			// expired certificates and old protocol versions. Certificates are
			// recorded and checked separately, and nothing secret is ever sent.
			InsecureSkipVerify: true,             // #nosec G402
			MinVersion:         tls.VersionTLS10, // #nosec G402
			CipherSuites:       allCipherSuites(),
		},
		TLSHandshakeTimeout:    r.opts.Timeout,
		ResponseHeaderTimeout:  r.opts.Timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return w
}

func (w *webClient) close() { w.transport.CloseIdleConnections() }

func allCipherSuites() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

// dial is the single point where discovery opens connections. It refuses any
// host or port outside the scope and only uses addresses checked by lookup.
func (w *webClient) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = normalizeHost(host)
	if !w.r.s.HostInScope(host) {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, host)
	}
	if p, err := strconv.Atoi(port); err != nil || !w.r.allowedPort(host, p) {
		return nil, fmt.Errorf("%w: port %s on %s", ErrOutOfScope, port, host)
	}
	res := w.r.lookup(ctx, host)
	if len(res.allowed) == 0 {
		if res.err != nil {
			return nil, res.err
		}
		return nil, fmt.Errorf("%w: %s has no address Hejnal may contact", ErrOutOfScope, host)
	}
	d := net.Dialer{Timeout: w.r.opts.Timeout}
	var last error
	for _, ip := range res.allowed {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// probe checks one port. It returns nil when the port is closed. However a
// server behaves, the whole check ends within a fixed time.
func (w *webClient) probe(ctx context.Context, host string, port int) *inventory.Service {
	budget := probeBudget * w.r.opts.Timeout
	if w.r.opts.Checks {
		budget += checksBudget * w.r.opts.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := w.dial(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	c.Close()

	var found, fallback *inventory.Service
	for _, scheme := range schemesFor(port) {
		svc, wrongScheme, err := w.fetch(ctx, host, port, scheme)
		if err != nil {
			continue
		}
		if wrongScheme {
			fallback = svc
			continue
		}
		found = svc
		break
	}
	if found == nil {
		found = fallback
	}
	if found != nil {
		if w.r.opts.Checks {
			w.runChecks(ctx, host, port, found)
		}
		return found
	}
	svc := &inventory.Service{Port: port, Scheme: "tcp", Banner: w.banner(ctx, addr)}
	if svc.Banner != "" {
		svc.Technologies = w.r.opts.Engine.Identify(fingerprint.NewBanner(svc.Banner))
	}
	return svc
}

func schemesFor(port int) []string {
	switch port {
	case 80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000:
		return []string{"http", "https"}
	}
	return []string{"https", "http"}
}

// staticCopy asks for the page again with a rule's server check headers,
// as a browser does when it navigates in the application, and reports
// whether a plain file server answered. Errors and redirects count as the
// application, so a flaw is never hidden by a failed check.
func (w *webClient) staticCopy(ctx context.Context, page *url.URL, id string, headers map[string]string) bool {
	client := &http.Client{
		Transport:     w.transport,
		Timeout:       2 * w.r.opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, page.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", w.r.opts.UserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return w.r.opts.Engine.StaticCopy(id, resp.StatusCode, fingerprint.NewResponse(resp.Header, page.Path, string(body)))
}

// fetch sends one GET request for "/". It follows redirects only on the same
// host and to ports allowed for it. A redirect to another host is not
// followed: an in-scope target is noted and gets its own GET / in the next
// round. wrongScheme reports a plain-HTTP request answered with "use HTTPS".
func (w *webClient) fetch(ctx context.Context, host string, port int, scheme string) (svc *inventory.Service, wrongScheme bool, err error) {
	start := &url.URL{Scheme: scheme, Host: hostPort(host, port, scheme), Path: "/"}
	var hops []*http.Response
	client := &http.Client{
		Transport: w.transport,
		Timeout:   2 * w.r.opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects || req.URL.User != nil {
				return http.ErrUseLastResponse
			}
			if next := normalizeHost(req.URL.Hostname()); next != host {
				w.r.noteName(next, SourceRedirect)
				return http.ErrUseLastResponse
			}
			if !w.r.allowedPort(host, urlPort(req.URL)) {
				return http.ErrUseLastResponse
			}
			if req.Response != nil {
				hops = append(hops, req.Response)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, start.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", w.r.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	final := resp.Request.URL
	header := mergeHeaders(resp, hops)
	fr := fingerprint.NewResponse(header, final.Path, string(body))
	svc = &inventory.Service{
		Port:         port,
		Scheme:       scheme,
		URL:          start.String(),
		Status:       resp.StatusCode,
		Title:        fr.Title,
		Server:       truncate(header.Get("Server"), 120),
		Technologies: w.r.opts.Engine.Identify(fr),
	}
	if f := final.String(); f != svc.URL {
		svc.FinalURL = f
	}
	w.r.surface(host, svc, string(body))
	w.r.noteScripts(host, port, final, string(body))
	for i, t := range svc.Technologies {
		if headers, ok := w.r.opts.Engine.ServerCheck(t.ID); ok && w.staticCopy(ctx, final, t.ID, headers) {
			svc.Technologies[i].Static = true
			svc.Technologies[i].Evidence += "; static files: no application answered the server check"
		}
	}

	// The certificate on the first hop belongs to the port being probed.
	first := resp
	if len(hops) > 0 {
		first = hops[0]
	}
	if leaf := leafCert(first); leaf != nil {
		svc.TLS = tlsInfo(leaf)
	}
	for _, r := range append(hops, resp) {
		if leaf := leafCert(r); leaf != nil {
			for _, n := range leaf.DNSNames[:min(len(leaf.DNSNames), maxSANs)] {
				w.r.noteName(n, SourceTLS)
			}
		}
	}

	wrongScheme = scheme == "http" && resp.StatusCode == http.StatusBadRequest && tlsHint.Match(body)
	return svc, wrongScheme, nil
}

// mergeHeaders adds headers and cookies from earlier responses on the same
// host to the final response, because products often reveal themselves on the
// redirect to their login page.
func mergeHeaders(final *http.Response, hops []*http.Response) http.Header {
	h := final.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	finalHost := final.Request.URL.Hostname()
	for _, hop := range hops {
		if hop.Request == nil || hop.Request.URL.Hostname() != finalHost {
			continue
		}
		for k, vs := range hop.Header {
			switch {
			case k == "Set-Cookie":
				h[k] = append(h[k], vs...)
			case len(h[k]) == 0:
				h[k] = slices.Clone(vs)
			}
		}
	}
	return h
}

func leafCert(r *http.Response) *x509.Certificate {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func tlsInfo(c *x509.Certificate) *inventory.TLSInfo {
	info := &inventory.TLSInfo{
		Subject:  c.Subject.CommonName,
		Issuer:   c.Issuer.CommonName,
		NotAfter: c.NotAfter.UTC(),
	}
	if info.Subject == "" {
		info.Subject = c.Subject.String()
	}
	if info.Issuer == "" {
		info.Issuer = c.Issuer.String()
	}
	names := c.DNSNames
	if len(names) > maxSANs {
		names = names[:maxSANs]
	}
	info.DNSNames = slices.Clone(names)
	return info
}

// banner reads what a non-web service says first, such as an SSH or SMTP
// greeting. It sends nothing.
func (w *webClient) banner(ctx context.Context, addr string) string {
	c, err := w.dial(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(bannerWait))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	return printable(buf[:n])
}

func printable(b []byte) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r == utf8.RuneError:
			return -1
		case unicode.IsSpace(r):
			return ' '
		case !unicode.IsPrint(r):
			return -1
		}
		return r
	}, string(b))
	return truncate(strings.Join(strings.Fields(s), " "), 120)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// urlPort returns the port a URL connects to.
func urlPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return -1
		}
		return n
	}
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return -1
}

func hostPort(host string, port int, scheme string) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
