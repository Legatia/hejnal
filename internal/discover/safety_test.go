package discover

// Regression tests for the scope guarantees: Hejnal must never contact a
// host, address or port outside the scope, whatever servers or DNS answer.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder is a test server that logs the requests it receives.
type recorder struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newRecorder(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *recorder {
	rec := &recorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.seen = append(rec.seen, r.Host+" "+r.URL.RequestURI()+" auth="+r.Header.Get("Authorization"))
		rec.mu.Unlock()
		if h != nil {
			h(w, r)
		}
	}))
	t.Cleanup(rec.Close)
	return rec
}

func (r *recorder) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

func TestRedirectsNeverLeaveTheHostOrPort(t *testing.T) {
	victim := newRecorder(t, nil) // a service on a port outside the scope
	vp := strconv.Itoa(portOf(t, victim.URL))
	var hostile *recorder
	hostile = newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.Host, "127.0.0.1") && r.URL.Path == "/":
			// Another listed host, a port outside the scope, a chosen path.
			http.Redirect(w, r, "http://intranet.example.test:"+vp+"/cgi-bin/x?cmd=id", http.StatusFound)
		case strings.HasPrefix(r.Host, "intranet.example.test") && r.URL.Path == "/":
			// The same host, but a port outside the scope.
			http.Redirect(w, r, "http://intranet.example.test:"+vp+"/", http.StatusFound)
		}
	})
	hp := portOf(t, hostile.URL)

	s := testScope(t, nil, []string{"127.0.0.1", "intranet.example.test"}, []int{hp}, nil)
	inv, err := Run(context.Background(), Options{
		Scope:    s,
		Engine:   engine(t),
		Resolver: fakeResolver{"intranet.example.test": {"127.0.0.1"}},
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := victim.requests(); len(got) != 0 {
		t.Fatalf("a port outside the scope was contacted: %q", got)
	}
	for _, req := range hostile.requests() {
		if strings.Contains(req, "cgi-bin") {
			t.Errorf("followed a redirect to a chosen path on another host: %q", req)
		}
	}
	// The redirect target is checked on its own, on its own allowed ports.
	if !slices.ContainsFunc(hostile.requests(), func(s string) bool {
		return strings.HasPrefix(s, "intranet.example.test:"+strconv.Itoa(hp)+" / ")
	}) {
		t.Errorf("intranet.example.test was not checked itself: %q", hostile.requests())
	}
	for _, a := range inv.Assets {
		for _, svc := range a.Services {
			if svc.Status != http.StatusFound || svc.FinalURL != "" {
				t.Errorf("%s:%d = status %d final %q, want the redirect itself", a.Host, svc.Port, svc.Status, svc.FinalURL)
			}
		}
	}
}

func TestRedirectWithCredentialsIsNotFollowed(t *testing.T) {
	srv := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "http://admin:hunter2@"+r.Host+"/login", http.StatusFound)
		}
	})
	s := testScope(t, nil, []string{"127.0.0.1"}, []int{portOf(t, srv.URL)}, nil)
	if _, err := Run(context.Background(), Options{Scope: s, Engine: engine(t), Timeout: 2 * time.Second}); err != nil {
		t.Fatal(err)
	}
	for _, req := range srv.requests() {
		if !strings.HasSuffix(req, "auth=") || strings.Contains(req, "/login") {
			t.Errorf("followed a redirect carrying credentials: %q", req)
		}
	}
}

func TestDialChecksPorts(t *testing.T) {
	s := testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{8443}, nil)
	r, err := newRunner(Options{
		Scope:    s,
		Engine:   engine(t),
		Resolver: fakeResolver{"app.example.test": {"8.8.8.8"}},
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.web.close()
	for _, addr := range []string{
		"app.example.test:8443", // names found under a domain get web ports only
		"app.example.test:22",
		"127.0.0.1:22",  // listed hosts get the configured ports only
		"127.0.0.1:443", // 443 is not configured for listed hosts here
	} {
		if _, err := r.web.dial(context.Background(), "tcp", addr); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("dial(%s) error = %v, want ErrOutOfScope", addr, err)
		}
	}
	if _, err := r.web.dial(context.Background(), "tcp", "127.0.0.1:8443"); errors.Is(err, ErrOutOfScope) {
		t.Errorf("dial(127.0.0.1:8443) was refused as out of scope")
	}
}

func TestAddressRules(t *testing.T) {
	s := testScope(t, []string{"example.test"}, []string{"listed.example.test", "203.0.113.7"}, nil,
		[]string{"192.0.2.0/24", "legacy.example.test"})
	r, err := newRunner(Options{
		Scope:    s,
		Engine:   engine(t),
		Resolver: fakeResolver{"legacy.example.test": {"198.51.100.20"}},
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.web.close()
	r.resolveExclusions(context.Background())

	cases := []struct {
		host, ip string
		want     bool
	}{
		{"app.example.test", "8.8.8.8", true},
		{"app.example.test", "2a00:1450:4001::1", true},
		{"app.example.test", "64:ff9b::808:808", true}, // NAT64 form of 8.8.8.8
		{"app.example.test", "10.0.0.1", false},
		{"app.example.test", "64:ff9b::a00:1", false},    // NAT64 form of 10.0.0.1
		{"app.example.test", "64:ff9b::c000:205", false}, // NAT64 form of excluded 192.0.2.5
		{"app.example.test", "64:ff9b:1::a00:1", false},  // local-use NAT64
		{"app.example.test", "::a00:1", false},
		{"app.example.test", "::ffff:0:a00:1", false},
		{"app.example.test", "2002:a00:1::1", false},
		{"app.example.test", "2001:0:a00:1::1", false},
		{"app.example.test", "fec0::1", false},
		{"app.example.test", "100::1", false},
		{"app.example.test", "3fff::1", false},
		{"app.example.test", "fe80::1", false},
		{"app.example.test", "198.51.100.20", false}, // address of an excluded host
		{"listed.example.test", "10.0.0.1", true},    // listed names may be internal
		{"listed.example.test", "127.0.0.1", false},
		{"listed.example.test", "0.0.0.0", false},
		{"listed.example.test", "169.254.169.254", false},
		{"listed.example.test", "203.0.113.7", true}, // listed address
		{"203.0.113.7", "203.0.113.7", true},
		{"203.0.113.8", "203.0.113.8", false},
	}
	for _, c := range cases {
		if got := r.allowedIP(c.host, netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("allowedIP(%s, %s) = %v, want %v", c.host, c.ip, got, c.want)
		}
	}
}

func TestExcludedHostsAddressesAreExcluded(t *testing.T) {
	srv := newRecorder(t, nil)
	port := portOf(t, srv.URL)
	// www is another name for the excluded machine, and its address is also
	// listed explicitly.
	s := testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, []string{"legacy.example.test"})
	inv, err := Run(context.Background(), Options{
		Scope:    s,
		Engine:   engine(t),
		Resolver: fakeResolver{"legacy.example.test": {"127.0.0.1"}, "www.example.test": {"127.0.0.1"}},
		WebPorts: []int{port},
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.requests(); len(got) != 0 {
		t.Fatalf("the excluded machine was contacted: %q", got)
	}
	www := assetMap(inv)["www.example.test"]
	if len(www.Errors) == 0 || !strings.Contains(www.Errors[0], "excluded") {
		t.Errorf("www.example.test = %+v, want it reported as not contacted", www)
	}
}

func TestLimits(t *testing.T) {
	var many []string
	for i := 1; i <= 50; i++ {
		many = append(many, fmt.Sprintf("8.8.%d.%d", i/250, i%250))
	}
	s := testScope(t, []string{"example.test"}, nil, nil, nil)
	r, err := newRunner(Options{
		Scope:    s,
		Engine:   engine(t),
		Resolver: fakeResolver{"big.example.test": many},
		MaxHosts: 10,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.web.close()
	res := r.lookup(context.Background(), "big.example.test")
	if len(res.allowed) != maxAddrsPerHost || len(res.all) != maxListedIPs {
		t.Errorf("allowed %d and listed %d addresses, want %d and %d", len(res.allowed), len(res.all), maxAddrsPerHost, maxListedIPs)
	}
	for i := 0; i < 100; i++ {
		r.noteName(fmt.Sprintf("n%d.example.test", i), SourceTLS)
	}
	if n := len(r.takeFound()); n > 10 {
		t.Errorf("kept %d names from certificates, want at most MaxHosts (10)", n)
	}
}

func TestCrtShDoesNotFollowRedirectsElsewhere(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "[]")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+strconv.Itoa(portOf(t, other.URL))+"/", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := (&CrtSh{Client: srv.Client(), BaseURL: srv.URL}).Subdomains(context.Background(), "example.test"); err == nil {
		t.Error("expected an error for a redirect to another host")
	}
	if hits.Load() != 0 {
		t.Error("followed a redirect to another host")
	}
}
