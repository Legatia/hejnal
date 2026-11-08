package discover

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
		{"Heroku", "shiny-app-1234.herokudns.com", nil, "<html><head><title>No such app</title></head></html>", "Heroku"},
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
			io.WriteString(w, "<html><title>Acme admin</title></html>")
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
