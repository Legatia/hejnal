package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// hostLog records the Host of every HTTP request a test server gets.
type hostLog struct {
	mu    sync.Mutex
	hosts []string
}

func (l *hostLog) handler(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	l.mu.Lock()
	l.hosts = append(l.hosts, host)
	l.mu.Unlock()
	io.WriteString(w, `<html><head><title>Acme</title></head><body><p>Welcome to Acme.</p></body></html>`)
}

func (l *hostLog) saw(host string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Contains(l.hosts, host)
}

// tiedServers starts a TLS server that shows each name the certificate a
// test gives it, and a plain HTTP server standing in for port 80. The TLS
// server's port becomes tiePort for the test.
func tiedServers(t *testing.T, certs map[string][]string) (tlsLog, plainLog *hostLog, tlsPort, plainPort int) {
	t.Helper()
	tlsLog, plainLog = &hostLog{}, &hostLog{}
	made := map[string]*tls.Certificate{}
	for host, names := range certs {
		if names != nil {
			c := testCert(t, names, testNow.Add(90*24*time.Hour))
			made[host] = &c
		}
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(tlsLog.handler))
	srv.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := made[hello.ServerName]; c != nil {
			return c, nil
		}
		return nil, errors.New("no certificate for this name")
	}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are the point
	srv.StartTLS()
	t.Cleanup(srv.Close)
	plain := httptest.NewServer(http.HandlerFunc(plainLog.handler))
	t.Cleanup(plain.Close)
	tlsPort, plainPort = portOf(t, srv.URL), portOf(t, plain.URL)
	old := tiePort
	tiePort = tlsPort
	t.Cleanup(func() { tiePort = old })
	return tlsLog, plainLog, tlsPort, plainPort
}

// Under TiedOnly, a name under the scope's domains gets HTTP requests only
// when its certificate names one of the scope's names; others get the TLS
// handshake and nothing else, on no port.
func TestTiedOnly(t *testing.T) {
	certs := map[string][]string{
		"tied.example.test":    {"tied.example.test"},
		"wild.example.test":    {"*.example.test"},
		"sibling.example.test": {"www.example.test", "api.example.test"},
		"untied.example.test":  {"www.someone-else.test", "someone-else.test"},
		"listed.example.test":  {"www.someone-else.test"},
		"notls.example.test":   nil,
	}
	tlsLog, plainLog, tlsPort, plainPort := tiedServers(t, certs)
	res := fakeResolver{}
	var names []string
	for n := range certs {
		res[n] = []string{"127.0.0.1"}
		names = append(names, n)
	}
	run := func(tiedOnly bool) map[string]bool {
		t.Helper()
		inv, err := Run(context.Background(), Options{
			Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1", "listed.example.test"}, []int{tlsPort, plainPort}, nil),
			Engine:   engine(t),
			Resolver: res,
			Names:    names,
			WebPorts: []int{tlsPort, plainPort},
			Timeout:  3 * time.Second,
			TiedOnly: tiedOnly,
			Now:      func() time.Time { return testNow },
		})
		if err != nil {
			t.Fatal(err)
		}
		services := map[string]bool{}
		for _, a := range inv.Assets {
			services[a.Host] = len(a.Services) > 0
			switch a.Host {
			case "untied.example.test":
				if tiedOnly && (len(a.Errors) != 1 || !strings.Contains(a.Errors[0], "names none of the scope's domains; it names www.someone-else.test, someone-else.test")) {
					t.Errorf("untied: %+v", a)
				}
			case "notls.example.test":
				if tiedOnly && (len(a.Errors) != 1 || !strings.Contains(a.Errors[0], "showed no TLS certificate")) {
					t.Errorf("no TLS: %+v", a)
				}
			}
		}
		return services
	}

	services := run(true)
	for _, host := range []string{"tied.example.test", "wild.example.test", "sibling.example.test", "listed.example.test"} {
		if !tlsLog.saw(host) || !plainLog.saw(host) || !services[host] {
			t.Errorf("%s: HTTPS %v, HTTP %v, services %v", host, tlsLog.saw(host), plainLog.saw(host), services[host])
		}
	}
	for _, host := range []string{"untied.example.test", "notls.example.test"} {
		if tlsLog.saw(host) || plainLog.saw(host) || services[host] {
			t.Errorf("%s was contacted: HTTPS %v, HTTP %v, services %v", host, tlsLog.saw(host), plainLog.saw(host), services[host])
		}
	}

	// Without TiedOnly, every name is looked at as before.
	run(false)
	if !tlsLog.saw("untied.example.test") || !plainLog.saw("notls.example.test") {
		t.Error("without TiedOnly, untied names were skipped")
	}
}

// A port 443 without TLS ties nothing: no name gets an HTTP request.
func TestTiedOnlyWithoutTLS(t *testing.T) {
	plainLog := &hostLog{}
	plain := httptest.NewServer(http.HandlerFunc(plainLog.handler))
	defer plain.Close()
	port := portOf(t, plain.URL)
	old := tiePort
	tiePort = port
	defer func() { tiePort = old }()
	inv, err := Run(context.Background(), Options{
		Scope:    testScope(t, []string{"example.test"}, []string{"127.0.0.1"}, []int{port}, nil),
		Engine:   engine(t),
		Resolver: fakeResolver{"example.test": {"127.0.0.1"}, "www.example.test": {"127.0.0.1"}},
		WebPorts: []int{port},
		Timeout:  3 * time.Second,
		TiedOnly: true,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if plainLog.saw("example.test") || plainLog.saw("www.example.test") {
		t.Errorf("requests: %q", plainLog.hosts)
	}
	for _, a := range inv.Assets {
		if a.Host != "127.0.0.1" && (len(a.Services) != 0 || len(a.Errors) != 1) {
			t.Errorf("%s: %+v", a.Host, a)
		}
	}
}

func TestCertTied(t *testing.T) {
	r := &runner{s: testScope(t, []string{"example.test", "acme.test"}, nil, []int{443}, nil)}
	parse := func(names ...string) *x509.Certificate {
		c, err := x509.ParseCertificate(testCert(t, names, testNow.Add(24*time.Hour)).Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, c := range []struct {
		host  string
		names []string
		want  bool
	}{
		{"shop.example.test", []string{"shop.example.test"}, true},
		{"shop.example.test", []string{"*.example.test"}, true},
		{"a.b.example.test", []string{"*.b.example.test"}, true},
		{"shop.example.test", []string{"www.acme.test"}, true}, // another of the scope's domains
		{"shop.example.test", []string{"*.test"}, false},
		{"shop.example.test", []string{"example.test.evil.test"}, false},
		{"shop.example.test", []string{"notexample.test"}, false},
		{"shop.example.test", []string{"someone-else.test", "www.someone-else.test"}, false},
	} {
		if got := r.certTied(c.host, parse(c.names...)); got != c.want {
			t.Errorf("%s with %v: %v", c.host, c.names, got)
		}
	}
	if r.certTied("shop.example.test", nil) {
		t.Error("no certificate tied a name")
	}
}
