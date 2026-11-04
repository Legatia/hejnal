package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

const (
	testToken = "3f9a1c0d5e7b2a4c6d8e0f1a3b5c7d9e" // hejnal:allow (test token)
	kevSample = "../testdata/kev_sample.json"
)

// logs collects log messages from any goroutine.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// newAPI serves the API over a local test server.
func newAPI(t *testing.T, cfg Config) (*httptest.Server, *logs) {
	t.Helper()
	l := &logs{}
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	cfg.Logf = l.logf
	cfg.Now = func() time.Time { return testNow }
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, l
}

// do sends a request, with the token when it is not empty.
func do(t *testing.T, srv *httptest.Server, method, path, token string, body io.Reader) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, data
}

func decode[T any](t *testing.T, data []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
	return v
}

// errorText returns the message of a JSON error response, failing the test
// if the body is not one.
func errorText(t *testing.T, data []byte) string {
	t.Helper()
	var e map[string]any
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatalf("error body is not JSON: %q", data)
	}
	msg, ok := e["error"].(string)
	if !ok || msg == "" || len(e) != 1 {
		t.Fatalf(`error body is not {"error": "..."}: %s`, data)
	}
	return msg
}

// site is a local WordPress-on-PHP site. While blocked, it holds requests
// until released, so a run stays in progress.
type site struct {
	URL     string
	hits    chan struct{}
	release chan struct{}
	once    sync.Once
}

func newSite(t *testing.T, blocked bool) *site {
	t.Helper()
	s := &site{hits: make(chan struct{}, 16), release: make(chan struct{})}
	if !blocked {
		s.unblock()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.hits <- struct{}{}:
		default:
		}
		select {
		case <-s.release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
		io.WriteString(w, `<html><head><title>Sklep</title><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	}))
	t.Cleanup(func() {
		s.unblock()
		srv.Close()
	})
	s.URL = srv.URL
	return s
}

func (s *site) unblock() { s.once.Do(func() { close(s.release) }) }

// waitHit waits until the site receives a request.
func (s *site) waitHit(t *testing.T) {
	t.Helper()
	select {
	case <-s.hits:
	case <-time.After(10 * time.Second):
		t.Fatal("the site was never contacted")
	}
}

// siteScope authorises checking the site on 127.0.0.1.
func siteScope(t *testing.T, siteURL string) func() (*scope.Scope, error) {
	t.Helper()
	u, err := url.Parse(siteURL)
	if err != nil {
		t.Fatal(err)
	}
	data := `{
  "organization": "Sklep Sp. z o.o.",
  "authorization": {"confirmedBy": "Anna Nowak, IT", "date": "2026-11-01", "statement": "We own this system."},
  "hosts": ["127.0.0.1"],
  "ports": [` + u.Port() + `]
}`
	return func() (*scope.Scope, error) { return scope.Parse([]byte(data), testNow) }
}

// newEngine makes an engine that never leaves this machine.
func newEngine(t *testing.T, dir, kevFile string) *engine.Engine {
	t.Helper()
	e, err := engine.New(engine.Config{
		StateDir: dir,
		KEVFile:  kevFile,
		NoEPSS:   true,
		NoCT:     true,
		NoNVD:    true,
		Timeout:  10 * time.Second,
		Now:      func() time.Time { return testNow },
		Logf:     (&logs{}).logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// fixture findings, most urgent first: two WordPress flaws and one the
// version check rules out, an expired certificate, and a Jenkins admin page
// with a known exploited flaw.
func fixtureFindings() []match.Finding {
	expired := testNow.Add(-48 * time.Hour)
	wp := match.Finding{Kind: match.KindKEV, Host: "shop.example.com", Port: 443, URL: "https://shop.example.com/",
		TechID: "wordpress", Technology: "WordPress", Version: "6.8.1", Category: "cms", Confidence: match.ConfidenceProduct}
	jenkins := match.Finding{Host: "10.0.0.5", Port: 8080, URL: "http://10.0.0.5:8080/", TechID: "jenkins",
		Technology: "Jenkins", Version: "2.440", Category: "devops"}
	fs := []match.Finding{
		withKEV(wp, "CVE-2026-119977", "WordPress Core Code Injection Vulnerability", "2026-11-03", 85, true),
		withKEV(wp, "CVE-2026-87902", "WordPress Core Cross-Site Scripting Vulnerability", "2026-09-25", 75, false),
		{Key: "tls-expired|mail.example.com|443", Kind: match.KindTLSExpired, Host: "mail.example.com", Port: 443,
			URL: "https://mail.example.com/", Subject: "mail.example.com", Expires: &expired, Score: 70,
			Severity: match.High, Confidence: match.ConfidenceObserved},
	}
	admin := jenkins
	admin.Kind, admin.Key, admin.Score, admin.Severity, admin.Confidence = match.KindAdminExposed,
		"admin-exposed|10.0.0.5|8080|jenkins", 55, match.Medium, match.ConfidenceObserved
	cli := withKEV(jenkins, "CVE-2024-23897", "Jenkins Command Line Interface (CLI) Path Traversal Vulnerability", "2024-08-19", 50, false)
	cli.Confidence, cli.Ransomware = match.ConfidenceProduct, true
	old := withKEV(wp, "CVE-2025-11111", "WordPress Core Path Traversal Vulnerability", "2025-04-01", 20, false)
	old.Confidence = match.ConfidenceRuledOut
	fs = append(fs, admin, cli, old)
	match.Sort(fs)
	return fs
}

func withKEV(base match.Finding, cve, name, added string, score int, forensics bool) match.Finding {
	f := base
	f.Kind = match.KindKEV
	f.Key = fmt.Sprintf("kev|%s|%d|%s", f.Host, f.Port, cve)
	f.CVE, f.Name, f.DateAdded, f.Score, f.Forensics = cve, name, added, score, forensics
	f.Severity = match.SeverityFor(score)
	return f
}

// writeState saves fixture findings and an inventory as a run would, and
// returns the store.
func writeState(t *testing.T, dir string) state.Store {
	t.Helper()
	store := state.Store{Dir: dir}
	snap := &state.Snapshot{
		Organization: "Sklep Sp. z o.o.",
		GeneratedAt:  testNow,
		KEVVersion:   "2026.11.03",
		Assets:       3,
		Services:     3,
		Technologies: 2,
		Findings:     fixtureFindings(),
	}
	if err := store.SaveFindings(snap); err != nil {
		t.Fatal(err)
	}
	expired := testNow.Add(-48 * time.Hour)
	inv := &inventory.Inventory{
		Organization: "Sklep Sp. z o.o.",
		GeneratedAt:  testNow,
		Assets: []inventory.Asset{
			{Host: "shop.example.com", Source: "domain", IPs: []string{"203.0.113.10"}, Services: []inventory.Service{{
				Port: 443, Scheme: "https", URL: "https://shop.example.com/", Status: 200, Title: "Sklep",
				Technologies: []inventory.Technology{{ID: "wordpress", Name: "WordPress", Version: "6.8.1", Category: "cms", Evidence: "generator WordPress 6.8.1"}},
			}}},
			{Host: "mail.example.com", Source: "ct", IPs: []string{"203.0.113.11"}, Services: []inventory.Service{{
				Port: 443, Scheme: "https", URL: "https://mail.example.com/", Status: 200,
				TLS: &inventory.TLSInfo{Subject: "mail.example.com", Issuer: "R11", NotAfter: expired},
			}}},
			{Host: "10.0.0.5", Source: "host", IPs: []string{"10.0.0.5"}, Services: []inventory.Service{{
				Port: 8080, Scheme: "http", URL: "http://10.0.0.5:8080/", Status: 403, Title: "Sign in [Jenkins]",
				Technologies: []inventory.Technology{{ID: "jenkins", Name: "Jenkins", Version: "2.440", Category: "devops", Admin: true, Evidence: "header X-Jenkins: 2.440"}},
			}}},
		},
	}
	if err := store.SaveInventory(inv); err != nil {
		t.Fatal(err)
	}
	return store
}

func keys(fs []match.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Key
	}
	return out
}
