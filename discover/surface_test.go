package discover

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
)

// fakeDNS is a resolver with CNAME, TXT and MX records.
type fakeDNS struct {
	fakeResolver
	cname map[string]string
	txt   map[string][]string
	mx    map[string][]string
	fail  map[string]bool // names whose TXT lookup times out
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[strings.TrimSuffix(host, ".")]; ok {
		return c + ".", nil
	}
	return host, nil
}

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if f.fail[name] {
		return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	}
	if t, ok := f.txt[name]; ok {
		return t, nil
	}
	return nil, notFound(name)
}

func (f fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	var out []*net.MX
	for _, h := range f.mx[strings.TrimSuffix(name, ".")] {
		out = append(out, &net.MX{Host: h + ".", Pref: 10})
	}
	if len(out) == 0 {
		return nil, notFound(name)
	}
	return out, nil
}

func TestTakeover(t *testing.T) {
	gh := "<html><body><h1>404</h1><p><strong>There isn't a GitHub Pages site here.</strong></p></body></html>"
	cases := []struct {
		name, cname string
		addrs       []string
		body        string
		want        string
	}{
		{"GitHub Pages by CNAME", "acme.github.io", nil, gh, "GitHub Pages"},
		{"GitHub Pages by address", "", []string{"185.199.110.153"}, gh, "GitHub Pages"},
		{"Heroku", "shiny-app-1234.herokuapp.com", nil, "<html><head><title>No such app</title></head></html>", "Heroku"},
		// Heroku's DNS targets are random per domain and cannot be claimed.
		{"Heroku DNS target", "shiny-app-1234.herokudns.com", nil, "<html><head><title>No such app</title></head></html>", ""},
		{"Heroku SSL target", "shiny-app-1234.herokussl.com", nil, "<html><head><title>No such app</title></head></html>", ""},
		{"S3", "assets.example.com.s3.eu-central-1.amazonaws.com", nil, "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>", "Amazon S3"},
		{"S3 website", "assets.example.com.s3-website-us-east-1.amazonaws.com", nil, "<Code>NoSuchBucket</Code>", "Amazon S3"},
		// The service's error text alone, without the name pointing there,
		// is somebody's page about it.
		{"text without the CNAME", "", []string{"203.0.113.7"}, gh, ""},
		{"CNAME with a working site", "acme.github.io", nil, "<html><title>Acme</title></html>", ""},
	}
	for _, c := range cases {
		var addrs []netip.Addr
		for _, a := range c.addrs {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		got, ok := takeover(c.cname, addrs, c.body)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s: %q, %v", c.name, got, ok)
		}
	}
}

func TestListingAndNonProduction(t *testing.T) {
	s3 := `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>acme</Name><Contents><Key>backup.sql</Key></Contents><Contents><Key>users.csv</Key></Contents></ListBucketResult>`
	if kind, ev := listing(s3); kind != ExposureBucketListing || strings.Contains(ev, "backup.sql") {
		t.Errorf("S3 listing: %q %q", kind, ev)
	}
	index := `<html><head><title>Index of /exports</title></head><body><h1>Index of /exports</h1><a href="../">Parent</a><a href="q3.xlsx">q3.xlsx</a></body></html>`
	if kind, ev := listing(index); kind != ExposureDirListing || strings.Contains(ev, "q3") {
		t.Errorf("folder listing: %q %q", kind, ev)
	}
	if kind, _ := listing(`<html><title>Index of our products</title></html>`); kind != "" {
		t.Errorf("an ordinary page counted as a listing: %q", kind)
	}
	for host, want := range map[string]bool{
		"staging.example.com": true, "dev2.example.com": true, "api-staging.example.com": true, "uat.shop.example.com": true,
		"www.example.com": false, "developers.example.com": false, "testimonials.example.com": false, "203.0.113.5": false,
	} {
		if got := nonProductionName(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}

func TestMailProblems(t *testing.T) {
	cases := []struct {
		m    inventory.MailAuth
		want string
	}{
		{inventory.MailAuth{SPF: "v=spf1 include:_spf.google.com -all", SPFKnown: true, DMARC: "v=DMARC1; p=reject; rua=mailto:d@example.com", DMARCKnown: true}, ""},
		{inventory.MailAuth{SPFKnown: true, DMARCKnown: true}, "spf-missing dmarc-missing"},
		{inventory.MailAuth{SPF: "v=spf1 +all", SPFKnown: true}, "spf-weak"},
		{inventory.MailAuth{SPF: "v=spf1 include:mailgun.org", SPFKnown: true}, "spf-weak"},
		{inventory.MailAuth{SPF: "v=spf1 redirect=_spf.example.com", SPFKnown: true}, ""},
		{inventory.MailAuth{DMARC: "v=DMARC1; p=none; rua=mailto:d@example.com", DMARCKnown: true}, "dmarc-none"},
		{inventory.MailAuth{DMARC: "v=DMARC1; rua=mailto:d@example.com", DMARCKnown: true}, "dmarc-missing"},
		// A lookup that failed says nothing.
		{inventory.MailAuth{}, ""},
		// An enforced DMARC policy already turns fake email away; a missing
		// SPF record is a lesser problem then.
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=reject", DMARCKnown: true}, "spf-missing-dmarc"},
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=quarantine; pct=100", DMARCKnown: true}, "spf-missing-dmarc"},
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=reject; pct=20", DMARCKnown: true}, "spf-missing"},
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=reject; t=y", DMARCKnown: true}, "spf-missing"},
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=reject"}, "spf-missing"},
		// A parent domain's record applies with its subdomain policy.
		{inventory.MailAuth{DMARC: "v=DMARC1; p=reject; sp=none", DMARCDomain: "example.com", DMARCKnown: true}, "dmarc-none"},
		{inventory.MailAuth{DMARC: "v=DMARC1; p=none; sp=reject", DMARCDomain: "example.com", DMARCKnown: true}, ""},
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=reject", DMARCDomain: "example.com", DMARCKnown: true}, "spf-missing-dmarc"},
		{inventory.MailAuth{SPFKnown: true, DMARC: "v=DMARC1; p=reject; sp=none", DMARCDomain: "example.com", DMARCKnown: true}, "spf-missing dmarc-none"},
		// sp= is only for subdomains; the domain's own record uses p=.
		{inventory.MailAuth{DMARC: "v=DMARC1; p=none; sp=reject", DMARCKnown: true}, "dmarc-none"},
	}
	for _, c := range cases {
		if got := strings.Join(c.m.Problems(), " "); got != c.want {
			t.Errorf("%+v: %q, want %q", c.m, got, c.want)
		}
	}
}

func TestSameOriginScripts(t *testing.T) {
	page, _ := url.Parse("https://www.example.com/shop/")
	body := `<script src="/static/app.js"></script><script defer src='chunk.js?v=2'></script>
<script src="https://cdn.example.net/lib.js"></script><script src="//www.example.com/static/app.js"></script>
<script src="http://www.example.com/insecure.js"></script><script>inline()</script>`
	got := sameOriginScripts(page, body)
	if strings.Join(got, " ") != "/static/app.js /shop/chunk.js?v=2" {
		t.Errorf("scripts = %q", got)
	}
}

// TestSurface runs discovery against names that show each problem.
func TestSurface(t *testing.T) {
	key := "sk_" + "live_" + strings.Repeat("4eC39HqLyjWDarjtT1zdp7dc", 2) // never a literal key in source
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		switch {
		case host == "old.example.test":
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "<p>There isn't a GitHub Pages site here.</p>")
		case host == "files.example.test":
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Contents><Key>a.csv</Key></Contents></ListBucketResult>`)
		case host == "staging.example.test":
			io.WriteString(w, `<html><head><title>Acme admin</title><meta name="robots" content="noindex, nofollow"></head><body><p>Orders, customers and reports for the Acme shop team.</p></body></html>`)
		case host == "www.example.test" && r.URL.Path == "/":
			io.WriteString(w, `<html><title>Acme</title><script src="/app.js"></script></html>`)
		case host == "www.example.test" && r.URL.Path == "/app.js":
			io.WriteString(w, `const stripe=Stripe("pk_live_x");const k="`+key+`";`)
		default:
			io.WriteString(w, "<html><title>Acme</title></html>")
		}
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	names := []string{"example.test", "www.example.test", "old.example.test", "files.example.test", "staging.example.test"}
	res := fakeResolver{}
	for _, n := range names {
		res[n] = []string{"127.0.0.1"}
	}
	dns := fakeDNS{fakeResolver: res,
		cname: map[string]string{"old.example.test": "acme.github.io"},
		txt:   map[string][]string{"example.test": {"google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"}},
		mx:    map[string][]string{"example.test": {"aspmx.l.google.com"}},
	}
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, nil),
		Engine:   engine(t),
		Resolver: dns,
		CT:       fakeCT{"example.test": {"old.example.test", "files.example.test", "staging.example.test"}},
		WebPorts: []int{port},
		Timeout:  3 * time.Second,
		Checks:   true,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]inventory.Exposure{}
	for _, a := range inv.Assets {
		for _, s := range a.Services {
			for _, x := range s.Exposures {
				got[a.Host+" "+x.Kind] = x
			}
		}
	}
	for _, want := range []string{"old.example.test takeover", "files.example.test bucket-listing", "staging.example.test non-production", "www.example.test script-secret"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, keys(got))
		}
	}
	if ev := got["www.example.test script-secret"].Evidence; strings.Contains(ev, key) || !strings.Contains(ev, "Stripe") {
		t.Errorf("script evidence = %q", ev)
	}
	if len(got) != 4 {
		t.Errorf("unexpected exposures: %v", keys(got))
	}
	if len(inv.Mail) != 1 || inv.Mail[0].SPF != "v=spf1 include:_spf.google.com ~all" || !inv.Mail[0].DMARCKnown || inv.Mail[0].DMARC != "" {
		t.Fatalf("mail = %+v", inv.Mail)
	}
	if p := inv.Mail[0].Problems(); fmt.Sprint(p) != "[dmarc-missing]" {
		t.Errorf("problems = %v", p)
	}

	// A DNS lookup that times out is not a missing record.
	dns.fail = map[string]bool{"_dmarc.example.test": true}
	inv, err = Run(context.Background(), Options{Scope: testScope(t, []string{"example.test"}, nil, []int{port}, nil),
		Engine: engine(t), Resolver: dns, WebPorts: []int{port}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Mail) != 1 || inv.Mail[0].DMARCKnown || len(inv.Mail[0].Problems()) != 0 {
		t.Errorf("after a timeout: %+v", inv.Mail)
	}
}

func keys(m map[string]inventory.Exposure) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Names from a DNS provider are looked at, and only within the scope.
func TestNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><title>Acme</title></html>")
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	res := fakeResolver{"example.test": {"127.0.0.1"}, "intranet-old.example.test": {"127.0.0.1"}, "other.test": {"127.0.0.1"}}
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, nil),
		Engine:   engine(t),
		Resolver: res,
		Names:    []string{"intranet-old.example.test", "other.test"},
		WebPorts: []int{port},
		Timeout:  3 * time.Second,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, a := range inv.Assets {
		found[a.Host] = a.Source
	}
	if found["intranet-old.example.test"] != SourceDNS {
		t.Errorf("the provider's name was not looked at: %v", found)
	}
	if _, ok := found["other.test"]; ok {
		t.Error("a name outside the scope was looked at")
	}
}

// testCA makes a certificate authority, trusted as certRoots for the test,
// and returns a function that issues certificates from it, and the key of
// every certificate it issues.
func testCA(t *testing.T) (func(notAfter time.Time, names ...string) *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: testNow.Add(-10 * 365 * 24 * time.Hour), NotAfter: testNow.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	old := certRoots
	certRoots = pool
	t.Cleanup(func() { certRoots = old })
	serial := int64(1)
	return func(notAfter time.Time, names ...string) *x509.Certificate {
		serial++
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
			NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}, key
}

func TestForeignHost(t *testing.T) {
	issue, _ := testCA(t)
	valid := testNow.Add(60 * 24 * time.Hour)
	public := func(names ...string) []*x509.Certificate { return []*x509.Certificate{issue(valid, names...)} }
	selfSigned := func(names ...string) []*x509.Certificate {
		c, err := x509.ParseCertificate(testCert(t, names, valid).Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return []*x509.Certificate{c}
	}
	r := &runner{s: testScope(t, []string{"example.test"}, nil, []int{443}, nil), cnames: map[string]string{
		"app.example.test":    "acme-shop.herokuapp.com",
		"api.example.test":    "sushi-4821.herokudns.com",
		"static.example.test": "www.example.test.edgekey.net",
		"cdn.example.test":    "acme.other-cdn.test",
	}}
	cases := []struct {
		host  string
		chain []*x509.Certificate
		want  bool
		names string
	}{
		{"old-api.example.test", public("shop.someone-else.test", "www.someone-else.test"), true, "shop.someone-else.test, www.someone-else.test"},
		{"a.example.test", public("x1.other.test", "x2.other.test", "x3.other.test", "x4.other.test"), true, "x1.other.test, x2.other.test, x3.other.test and 1 more"},
		// An expired certificate still shows whose it was.
		{"b.example.test", []*x509.Certificate{issue(testNow.Add(-24*time.Hour), "www.someone-else.test")}, true, "www.someone-else.test"},
		// The certificate covers the name.
		{"www.example.test", public("*.example.test"), false, ""},
		// A certificate for another of your names: yours, merely wrong here.
		{"c.example.test", public("www.example.test", "elsewhere.test"), false, ""},
		// No public authority vouches for a self-signed certificate.
		{"d.example.test", selfSigned("www.someone-else.test"), false, ""},
		{"nas.example.test", selfSigned("localhost"), false, ""},
		// Internal names: a cloud machine's own, an appliance's.
		{"e.example.test", public("ip-172-31-5-10.eu-west-1.compute.internal"), false, ""},
		{"f.example.test", public("nas.local", "router.home.arpa", "fritz.box.lan"), false, ""},
		// A hosting provider's own certificate on a name pointed at it.
		{"app.example.test", public("*.herokuapp.com", "herokuapp.com"), false, ""},
		{"api.example.test", public("*.herokuapp.com"), false, ""},
		{"static.example.test", public("a248.e.akamai.net", "*.akamaihd.net"), false, ""},
		// Pointed at a service, but showing a third party's certificate.
		{"cdn.example.test", public("www.someone-else.test"), true, "www.someone-else.test"},
		// Addresses are not names anyone rates you by.
		{"127.0.0.1", public("someone-else.test"), false, ""},
		{"g.example.test", nil, false, ""},
	}
	for _, c := range cases {
		names, ok := r.foreignHost(c.host, c.chain)
		if ok != c.want || names != c.names {
			t.Errorf("%s: %q, %v", c.host, names, ok)
		}
	}
}

// Under TiedOnly, a name whose server shows a public certificate for other
// names only is reported like a foreign host, without any HTTP request.
func TestTiedOnlyReportsForeignHosts(t *testing.T) {
	issue, key := testCA(t)
	valid := testNow.Add(60 * 24 * time.Hour)
	certs := map[string]tls.Certificate{
		"tied.example.test":  {Certificate: [][]byte{issue(valid, "tied.example.test").Raw}, PrivateKey: key},
		"gone.example.test":  {Certificate: [][]byte{issue(valid, "www.someone-else.test").Raw}, PrivateKey: key},
		"snake.example.test": testCert(t, []string{"ip-172-31-5-10.eu-west-1.compute.internal"}, valid),
	}
	log := &hostLog{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(log.handler))
	srv.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := certs[hello.ServerName]
		return &c, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	port := portOf(t, srv.URL)
	old := tiePort
	tiePort = port
	defer func() { tiePort = old }()
	res := fakeResolver{}
	var names []string
	for n := range certs {
		res[n] = []string{"127.0.0.1"}
		names = append(names, n)
	}
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, nil),
		Engine:   engine(t),
		Resolver: res,
		Names:    names,
		WebPorts: []int{port},
		Timeout:  3 * time.Second,
		TiedOnly: true,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string]inventory.Asset{}
	for _, a := range inv.Assets {
		assets[a.Host] = a
	}
	if !log.saw("tied.example.test") || log.saw("gone.example.test") || log.saw("snake.example.test") {
		t.Errorf("requests: %q", log.hosts)
	}
	gone := assets["gone.example.test"]
	if len(gone.Services) != 1 || len(gone.Services[0].Exposures) != 1 || gone.Services[0].Exposures[0].Kind != ExposureForeignHost ||
		gone.Services[0].Exposures[0].Evidence != "its certificate names none of the domains in your scope; it names www.someone-else.test" ||
		gone.Services[0].TLS != nil || len(gone.Errors) != 1 {
		t.Errorf("gone: %+v", gone)
	}
	if snake := assets["snake.example.test"]; len(snake.Services) != 0 || len(snake.Errors) != 1 {
		t.Errorf("self-signed: %+v", snake)
	}
}

// Scripts often carry AWS's documented example keys and private key
// placeholders from libraries; only a real, complete key is a leak.
func TestScriptSecretsSkipExamples(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	real := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE " + "KEY", Bytes: der})), "\n", `\n`)
	begin, end := "-----BEGIN PRIVATE "+"KEY-----", "-----END PRIVATE "+"KEY-----"
	examples := `var aws={accessKeyId:"AKIA` + `IOSFODNN7EXAMPLE",secretAccessKey:"wJalrXUtnFEMI/K7MDENG/` + `bPxRfiCYEXAMPLEKEY"};` + // hejnal:allow (the example key from AWS's documentation)
		`var doc="` + begin + `\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ...\n-----END";` +
		`var tpl="` + begin + `\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n` + end + `";` +
		`if(k.indexOf("` + begin + `")===0){}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `<html><title>Acme</title><script src="/lib.js"></script><script src="/app.js"></script></html>`)
		case "/lib.js":
			io.WriteString(w, examples)
		case "/app.js":
			if r.Host != "" && strings.HasPrefix(r.Host, "leaky.") {
				io.WriteString(w, `const key="`+real+`";`)
				return
			}
			io.WriteString(w, "init();")
		}
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	res := fakeResolver{"example.test": {"127.0.0.1"}, "www.example.test": {"127.0.0.1"}, "leaky.example.test": {"127.0.0.1"}}
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, nil),
		Engine:   engine(t),
		Resolver: res,
		Names:    []string{"leaky.example.test"},
		WebPorts: []int{port},
		Timeout:  3 * time.Second,
		Checks:   true,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range inv.Assets {
		for _, s := range a.Services {
			for _, x := range s.Exposures {
				got[a.Host] = x.Kind + ": " + x.Evidence
			}
		}
	}
	if len(got) != 1 || !strings.Contains(got["leaky.example.test"], "Private key") || strings.Contains(got["leaky.example.test"], "lib.js") {
		t.Errorf("exposures = %q", got)
	}
}

// A subdomain without a DMARC record of its own is covered by its parent
// domain's record, as receivers do.
func TestDMARCFromParent(t *testing.T) {
	dns := fakeDNS{fakeResolver: fakeResolver{},
		txt: map[string][]string{
			"_dmarc.example.test":      {"v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.test"},
			"_dmarc.eu.other.test":     {"v=DMARC1; p=none"},
			"_dmarc.own.example.test":  {"v=DMARC1; p=none"},
			"timeout.example.test":     {"v=spf1 -all"},
			"shop.example.test":        {"v=spf1 include:_spf.example.net -all"},
			"_dmarc.nested.other.test": nil,
		},
	}
	run := func(domain string, fail ...string) inventory.MailAuth {
		t.Helper()
		d := dns
		d.fail = map[string]bool{}
		for _, f := range fail {
			d.fail[f] = true
		}
		r := &runner{opts: Options{Resolver: d, Timeout: time.Second}}
		m, ok := r.mailAuth(context.Background(), domain)
		if !ok {
			t.Fatal("no mail records")
		}
		return m
	}
	m := run("shop.example.test")
	if m.DMARC != "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.test" || m.DMARCDomain != "example.test" || !m.DMARCKnown ||
		m.DMARCPolicy() != "quarantine" || len(m.Problems()) != 0 {
		t.Errorf("subdomain: %+v, problems %v", m, m.Problems())
	}
	if m := run("own.example.test"); m.DMARCDomain != "" || fmt.Sprint(m.Problems()) != "[spf-missing dmarc-none]" {
		t.Errorf("own record: %+v, problems %v", m, m.Problems())
	}
	// The nearest record up the name applies.
	if m := run("shop.eu.other.test"); m.DMARCDomain != "eu.other.test" || fmt.Sprint(m.Problems()) != "[spf-missing dmarc-none]" {
		t.Errorf("nearest parent: %+v", m)
	}
	if m := run("deep.nested.other.test"); m.DMARC != "" || !m.DMARCKnown || fmt.Sprint(m.Problems()) != "[spf-missing dmarc-missing]" {
		t.Errorf("no record anywhere: %+v", m)
	}
	// A parent lookup that times out leaves DMARC unknown.
	if m := run("timeout.example.test", "_dmarc.example.test"); m.DMARCKnown || len(m.Problems()) != 0 || len(m.Errors) != 1 {
		t.Errorf("after a timeout: %+v, problems %v", m, m.Problems())
	}
	for domain, want := range map[string]string{
		"example.com":                 "",
		"shop.example.com":            "example.com",
		"a.b.example.co.uk":           "b.example.co.uk example.co.uk co.uk",
		"a.b.c.d.e.f.g.example.com":   "c.d.e.f.g.example.com d.e.f.g.example.com e.f.g.example.com f.g.example.com g.example.com example.com",
		"a.b.c.d.e.f.g.h.example.com": "d.e.f.g.h.example.com e.f.g.h.example.com f.g.h.example.com g.h.example.com h.example.com example.com",
	} {
		if got := strings.Join(dmarcParents(domain), " "); got != want {
			t.Errorf("dmarcParents(%s) = %q, want %q", domain, got, want)
		}
	}
}

// A name such as dev. or qa. alone is no proof of a test copy: the page has
// to show it too, and a login or an empty application page never does.
func TestNonProductionNeedsASign(t *testing.T) {
	text := "<p>Welcome to Acme. We make tools for small workshops across Europe since 1998.</p>"
	pages := map[string]struct {
		header, page string
	}{
		"www.example.test":     {"", "<html><head><title>Acme</title></head><body>" + text + "</body></html>"},
		"staging.example.test": {"X-Robots-Tag: noindex", "<html><head><title>Acme</title></head><body>" + text + "</body></html>"},
		"uat.example.test":     {"", "<html><head><title>Acme (UAT)</title></head><body>" + text + "</body></html>"},
		"preview.example.test": {"", "<html><head><title>Acme</title></head><body>" + text + "</body></html>"},
		"dev2.example.test":    {"", "<html><head><title>Acme</title></head><body><p>This is the staging environment.</p>" + text + "</body></html>"},
		// Public sites with such names.
		"qa.example.test":      {"", "<html><head><title>Acme Q&amp;A</title></head><body><p>Questions and answers about Acme tools, from our users and staff.</p></body></html>"},
		"dev.example.test":     {"", "<html><head><title>Acme Dev Center</title></head><body><p>Build on Acme: API reference, guides and examples for developers.</p></body></html>"},
		"sandbox.example.test": {"", "<html><head><title>Acme API Sandbox</title></head><body><p>Try every API call against test data before you go live with Acme.</p></body></html>"},
		// A single-page application looks the same with or without a login.
		"test.example.test": {"", `<html><head><title>Acme</title><script src="/app.js"></script></head><body><div id="root"></div><noscript>You need to enable JavaScript to run this app.</noscript></body></html>`},
		// A login page.
		"stage.example.test": {"", `<html><head><title>Acme</title></head><body>` + text + `<form><input name="user"><input type="password" name="pw"></form></body></html>`},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		p := pages[host]
		if k, v, ok := strings.Cut(p.header, ": "); ok {
			w.Header().Set(k, v)
		}
		io.WriteString(w, p.page)
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	res := fakeResolver{"example.test": {"127.0.0.1"}}
	var names []string
	for n := range pages {
		res[n] = []string{"127.0.0.1"}
		names = append(names, n)
	}
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, nil),
		Engine:   engine(t),
		Resolver: res,
		Names:    names,
		WebPorts: []int{port},
		Timeout:  3 * time.Second,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range inv.Assets {
		for _, s := range a.Services {
			for _, x := range s.Exposures {
				if x.Kind == ExposureNonProduction {
					got[a.Host] = x.Evidence
				}
			}
		}
	}
	want := map[string]string{
		"staging.example.test": "asks search engines not to index it",
		"uat.example.test":     `its title "Acme (UAT)" names it a test copy`,
		"preview.example.test": "shows the same page title as www.example.test",
		"dev2.example.test":    "the page calls itself a staging site",
	}
	for host, sign := range want {
		if !strings.Contains(got[host], sign) || !strings.Contains(got[host], "suggests a staging or test copy") {
			t.Errorf("%s: %q, want %q", host, got[host], sign)
		}
	}
	for host, ev := range got {
		if _, ok := want[host]; !ok {
			t.Errorf("%s flagged: %q", host, ev)
		}
	}
	if names := productionNames("api-staging.shop.example.com"); strings.Join(names, " ") != "shop.example.com www.shop.example.com api.shop.example.com" {
		t.Errorf("productionNames = %q", names)
	}
	// Text in the head, even after a script there, is not the page's own.
	if !shell(visibleText(`<html><head><script>init()</script><title>Acme tools for small workshops across Europe since 1998</title></head><body><div id="app"></div></body></html>`)) {
		t.Error("the head's text counted as the page's")
	}
}

// The front-page checks send nothing of their own; only the opt-in checks
// fetch the scripts a page loads.
func TestScriptsOnlyWithChecks(t *testing.T) {
	for _, checks := range []bool{false, true} {
		var seen []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.URL.Path)
			io.WriteString(w, `<html><title>Acme</title><script src="/app.js"></script></html>`)
		}))
		port := portOf(t, srv.URL)
		_, err := Run(context.Background(), Options{
			Scope:    testScope(t, nil, []string{"127.0.0.1"}, []int{port}, nil),
			Engine:   engine(t),
			Resolver: fakeResolver{},
			Timeout:  3 * time.Second,
			Checks:   checks,
			Now:      func() time.Time { return testNow },
		})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if fetched := slices.Contains(seen, "/app.js"); fetched != checks || seen[0] != "/" || !checks && len(seen) != 1 {
			t.Errorf("checks %v: requests %q", checks, seen)
		}
	}
}
