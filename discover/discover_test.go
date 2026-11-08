package discover

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/scope"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if !strings.HasSuffix(host, ".") {
		return nil, fmt.Errorf("%q is not fully qualified; search domains could apply", host)
	}
	host = strings.TrimSuffix(host, ".")
	ips, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

type fakeCT map[string][]string

func (f fakeCT) Subdomains(_ context.Context, d string) ([]string, error) { return f[d], nil }

func testScope(t *testing.T, domains, hosts []string, ports []int, exclude []string) *scope.Scope {
	t.Helper()
	s := &scope.Scope{
		Organization:  "Test Sp. z o.o.",
		Authorization: scope.Authorization{ConfirmedBy: "Test", Date: "2026-11-01", Statement: "Test systems."},
		Domains:       domains,
		Hosts:         hosts,
		Ports:         ports,
		Exclude:       exclude,
	}
	if err := s.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	return s
}

func testCert(t *testing.T, names []string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func engine(t *testing.T) *fingerprint.Engine {
	t.Helper()
	e, err := fingerprint.Default()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// fortiGate mimics an SSL VPN appliance: "/" redirects to the login page.
func fortiGate(t *testing.T, cert tls.Certificate) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/remote/login?lang=en", http.StatusFound)
		case "/remote/login":
			io.WriteString(w, `<html><head><title>Please Login</title></head><body><script>var fgt_lang = {};</script></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// wordPress mimics a WordPress site on PHP over plain HTTP.
func wordPress(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
		io.WriteString(w, `<html><head><title>Sklep</title><meta name="generator" content="WordPress 6.8.1"></head><body><img src="/wp-content/uploads/logo.png"></body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func assetMap(inv *inventory.Inventory) map[string]inventory.Asset {
	m := map[string]inventory.Asset{}
	for _, a := range inv.Assets {
		m[a.Host] = a
	}
	return m
}

func techIDs(s inventory.Service) []string {
	var ids []string
	for _, t := range s.Technologies {
		ids = append(ids, t.ID)
	}
	return ids
}

func TestRunDiscoversAndFingerprints(t *testing.T) {
	expired := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	forti := fortiGate(t, testCert(t, []string{"vpn.example.test", "mail.example.test", "other.invalid"}, expired))
	wp := wordPress(t)
	fortiPort, wpPort := portOf(t, forti.URL), portOf(t, wp.URL)

	s := testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{fortiPort, wpPort}, []string{"skip.example.test"})
	resolver := fakeResolver{
		"example.test":          {"127.0.0.1"},
		"vpn.example.test":      {"127.0.0.1"},
		"mail.example.test":     {"127.0.0.1"},
		"internal.example.test": {"10.1.2.3"},
		"skip.example.test":     {"192.0.2.50"},
	}
	ct := fakeCT{"example.test": {"internal.example.test", "skip.example.test", "gone.example.test", "evil.test"}}

	var logs []string
	inv, err := Run(context.Background(), Options{
		Scope:    s,
		Engine:   engine(t),
		Resolver: resolver,
		CT:       ct,
		WebPorts: []int{fortiPort, wpPort},
		Timeout:  3 * time.Second,
		Now:      func() time.Time { return testNow },
		Logf:     func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Organization != "Test Sp. z o.o." || !inv.GeneratedAt.Equal(testNow) {
		t.Errorf("inventory header = %q %v", inv.Organization, inv.GeneratedAt)
	}

	assets := assetMap(inv)
	var hosts []string
	for h := range assets {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	want := []string{"127.0.0.1", "example.test", "internal.example.test", "mail.example.test", "vpn.example.test"}
	if !slices.Equal(hosts, want) {
		t.Fatalf("hosts = %v, want %v (logs: %v)", hosts, want, logs)
	}

	sources := map[string]string{
		"127.0.0.1": SourceHost, "example.test": SourceDomain, "internal.example.test": SourceCT,
		"vpn.example.test": SourceTLS, "mail.example.test": SourceTLS,
	}
	for h, src := range sources {
		if got := assets[h].Source; got != src {
			t.Errorf("%s source = %q, want %q", h, got, src)
		}
	}

	internal := assets["internal.example.test"]
	if len(internal.Services) != 0 || len(internal.Errors) == 0 || !strings.Contains(internal.Errors[0], "private") {
		t.Errorf("internal.example.test must be recorded but not contacted: %+v", internal)
	}

	host := assets["127.0.0.1"]
	if len(host.Services) != 2 {
		t.Fatalf("127.0.0.1 services = %+v", host.Services)
	}
	for _, svc := range host.Services {
		switch svc.Port {
		case fortiPort:
			if svc.Scheme != "https" || svc.Status != 200 || !strings.HasSuffix(svc.FinalURL, "/remote/login?lang=en") {
				t.Errorf("FortiGate service = %+v", svc)
			}
			if !slices.Contains(techIDs(svc), "fortinet-fortigate") {
				t.Errorf("FortiGate not identified: %v", techIDs(svc))
			}
			if svc.TLS == nil || !svc.TLS.NotAfter.Equal(expired) || svc.TLS.Subject != "vpn.example.test" {
				t.Errorf("TLS info = %+v", svc.TLS)
			}
		case wpPort:
			if svc.Scheme != "http" || svc.Title != "Sklep" || svc.TLS != nil {
				t.Errorf("WordPress service = %+v", svc)
			}
			ids := techIDs(svc)
			if !slices.Contains(ids, "wordpress") || !slices.Contains(ids, "php") {
				t.Errorf("WordPress on PHP not identified: %v", ids)
			}
		}
	}
	if n := len(assets["vpn.example.test"].Services); n != 2 {
		t.Errorf("vpn.example.test (found in the certificate) has %d services, want 2", n)
	}
}

func TestRedirectOutOfScopeIsNotFollowed(t *testing.T) {
	var hits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer outside.Close()
	target := "http://localhost:" + strconv.Itoa(portOf(t, outside.URL)) + "/"
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer redirector.Close()

	s := testScope(t, nil, []string{"127.0.0.1"}, []int{portOf(t, redirector.URL)}, nil)
	inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatal("followed a redirect to a host outside the scope")
	}
	if len(inv.Assets) != 1 || len(inv.Assets[0].Services) != 1 {
		t.Fatalf("assets = %+v", inv.Assets)
	}
	if svc := inv.Assets[0].Services[0]; svc.Status != http.StatusFound || svc.FinalURL != "" {
		t.Errorf("service = %+v, want the redirect itself recorded", svc)
	}
}

func TestDialGuard(t *testing.T) {
	s := testScope(t, []string{"example.test"}, nil, nil, []string{"203.0.113.0/24"})
	r, err := newRunner(Options{
		Scope:  s,
		Engine: engine(t),
		Resolver: fakeResolver{
			"app.example.test":    {"127.0.0.1"},
			"cgnat.example.test":  {"100.64.0.10"},
			"listed.example.test": {"203.0.113.10"},
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.web.close()
	for _, addr := range []string{
		"localhost:80",            // not in scope
		"10.0.0.1:80",             // address not in scope
		"app.example.test:80",     // in scope, but resolves to loopback
		"cgnat.example.test:80",   // shared address space
		"listed.example.test:443", // resolves to an excluded range
	} {
		if _, err := r.web.dial(context.Background(), "tcp", addr); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("dial(%s) error = %v, want ErrOutOfScope", addr, err)
		}
	}
}

func TestPublicIP(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2a00:1450:4001::1": true,
		"10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "100.64.0.1": false, "0.0.0.1": false, "198.18.0.1": false,
		"fd00::1": false, "::1": false, "fe80::1": false, "2001:db8::1": false,
	} {
		if got := publicIP(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicIP(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := testScope(t, nil, []string{"127.0.0.1"}, []int{port}, nil)
	inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Assets) != 1 || len(inv.Assets[0].Services) != 1 {
		t.Fatalf("assets = %+v", inv.Assets)
	}
	if svc := inv.Assets[0].Services[0]; svc.Scheme != "tcp" || svc.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("service = %+v", svc)
	}
}

// TestBannerIdentifiesTheProduct checks that a mail server is recognised by
// its greeting.
func TestBannerIdentifiesTheProduct(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("220 mail.example.com ESMTP Exim 4.94.2 Tue, 04 Nov 2026 12:00:00 +0100\r\n"))
				c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := testScope(t, nil, []string{"127.0.0.1"}, []int{port}, nil)
	inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Assets) != 1 || len(inv.Assets[0].Services) != 1 {
		t.Fatalf("assets = %+v", inv.Assets)
	}
	svc := inv.Assets[0].Services[0]
	if len(svc.Technologies) != 1 {
		t.Fatalf("technologies = %+v", svc.Technologies)
	}
	// Exim's greeting looks the same in distribution packages, so its
	// version is never treated as an upstream build.
	if tech := svc.Technologies[0]; tech.ID != "exim" || tech.Version != "4.94.2" || !tech.Packaged {
		t.Errorf("technology = %+v", tech)
	}
}

func TestClosedPortsAndEmptyRanges(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens on this port now
	s := testScope(t, nil, []string{"127.0.0.1"}, []int{port}, nil)
	inv, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Assets) != 1 || len(inv.Assets[0].Services) != 0 {
		t.Errorf("assets = %+v, want the listed host with no services", inv.Assets)
	}
}

func TestCrtSh(t *testing.T) {
	var query url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		json.NewEncoder(w).Encode([]map[string]string{
			{"common_name": "example.test", "name_value": "example.test\nwww.example.test"},
			{"common_name": "*.example.test", "name_value": "*.example.test\nB.Example.Test."},
			{"common_name": "other.test", "name_value": "x.other.test\nadmin@example.test"},
		})
	}))
	defer srv.Close()

	c := &CrtSh{Client: srv.Client(), BaseURL: srv.URL, UserAgent: "hejnal-test"}
	names, err := c.Subdomains(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if query.Get("q") != "%.example.test" || query.Get("output") != "json" {
		t.Errorf("query = %v", query)
	}
	want := []string{"b.example.test", "example.test", "www.example.test"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusBadGateway)
	}))
	defer down.Close()
	if _, err := (&CrtSh{Client: down.Client(), BaseURL: down.URL}).Subdomains(context.Background(), "example.test"); err == nil {
		t.Error("expected an error on HTTP 502")
	}
}

func TestHelpers(t *testing.T) {
	if got := schemesFor(80); got[0] != "http" {
		t.Errorf("schemesFor(80) = %v", got)
	}
	if got := schemesFor(443); got[0] != "https" {
		t.Errorf("schemesFor(443) = %v", got)
	}
	for _, msg := range []string{
		"The plain HTTP request was sent to HTTPS port",
		"Client sent an HTTP request to an HTTPS server.",
		"You're speaking plain HTTP to an SSL-enabled server port.",
	} {
		if !tlsHint.MatchString(msg) {
			t.Errorf("tlsHint does not match %q", msg)
		}
	}
	if got := printable([]byte("220 mail.example.test ESMTP\r\n\x00\x01")); got != "220 mail.example.test ESMTP" {
		t.Errorf("printable = %q", got)
	}
	if got := hostPort("::1", 443, "https"); got != "[::1]" {
		t.Errorf("hostPort = %q", got)
	}
	if got := hostPort("example.test", 8443, "https"); got != "example.test:8443" {
		t.Errorf("hostPort = %q", got)
	}
}

// A Next.js app router page served by the application keeps its product;
// the same page as a static export on a file server is marked static.
func TestServerCheckTellsStaticExportsApart(t *testing.T) {
	page := `<html><head><title>Shop</title></head><body><script>self.__next_f=self.__next_f||[]</script></body></html>`
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("RSC") == "1" {
			w.Header().Set("Content-Type", "text/x-component")
			fmt.Fprint(w, "0:{}")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	}))
	defer app.Close()
	static := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	}))
	defer static.Close()
	appPort, staticPort := portOf(t, app.URL), portOf(t, static.URL)
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, nil, []string{"127.0.0.1"}, []int{appPort, staticPort}, nil),
		Engine:   engine(t),
		Resolver: fakeResolver{},
		WebPorts: []int{appPort, staticPort},
		Timeout:  3 * time.Second,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]bool{}
	for _, s := range assetMap(inv)["127.0.0.1"].Services {
		for _, tech := range s.Technologies {
			if tech.ID == "nextjs-app-router" {
				got[s.Port] = tech.Static
			}
		}
	}
	if st, ok := got[appPort]; !ok || st {
		t.Errorf("application: found %v, static %v", ok, st)
	}
	if st, ok := got[staticPort]; !ok || !st {
		t.Errorf("static export: found %v, static %v", ok, st)
	}
}
