package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/scope"
)

func TestLookAndAssessSaveNothing(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
		io.WriteString(w, `<html><head><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	}))
	defer site.Close()
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	port := func(raw string) int {
		u, _ := url.Parse(raw)
		p, _ := strconv.Atoi(u.Port())
		return p
	}
	s := &scope.Scope{
		Organization:  "Test",
		Authorization: scope.Authorization{ConfirmedBy: "Test", Date: "2026-11-01", Statement: "Test."},
		Hosts:         []string{"127.0.0.1"},
		Ports:         []int{port(site.URL), port(other.URL)},
	}
	if err := s.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	e, err := New(Config{
		StateDir: dir,
		KEVFile:  "../testdata/kev_sample.json",
		NoEPSS:   true,
		NoCT:     true,
		NoNVD:    true,
		NoEOL:    true,
		NoEUVD:   true,
		Timeout:  3 * time.Second,
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	inv, err := e.Look(ctx, s, []discover.Target{{Host: "127.0.0.1", Ports: []int{port(site.URL)}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Assets) != 1 || len(inv.Assets[0].Services) != 1 {
		t.Fatalf("assets = %+v, want the named service alone", inv.Assets)
	}
	if hits.Load() != 0 {
		t.Error("contacted a service that was not named")
	}
	snap, err := e.Assess(ctx, inv)
	if err != nil {
		t.Fatal(err)
	}
	if !match.AtLeast(match.Open(snap.Findings), match.Critical) {
		t.Errorf("findings = %+v, want the exploited WordPress flaws", snap.Findings)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		if f.Name() != "cache" {
			t.Errorf("the state directory holds %s: a look at one system must save nothing but the feed cache", f.Name())
		}
	}

	// No targets is no reason to look at the whole scope.
	inv, err = e.Look(ctx, s, nil, false)
	if err != nil || len(inv.Assets) != 0 || hits.Load() != 0 {
		t.Errorf("a look at no systems: %+v, %v, %d requests elsewhere", inv, err, hits.Load())
	}
}

func TestParseLiveURL(t *testing.T) {
	for _, tc := range []struct {
		in, shown, host string
		port            int
		path            string
	}{
		{"https://app.example.com", "https://app.example.com", "app.example.com", 443, ""},
		{"App.Example.com.", "https://app.example.com", "app.example.com", 443, ""},
		{"http://app.example.com/", "http://app.example.com", "app.example.com", 80, ""},
		{"app.example.com:8443/login", "https://app.example.com:8443", "app.example.com", 8443, "/login"},
		{"https://app.example.com:443/", "https://app.example.com", "app.example.com", 443, ""},
		{"http://[2001:db8::1]:8080", "http://[2001:db8::1]:8080", "2001:db8::1", 8080, ""},
		{"https://[2001:db8::1]", "https://[2001:db8::1]", "2001:db8::1", 443, ""},
	} {
		got, err := ParseLiveURL(tc.in)
		if err != nil {
			t.Errorf("ParseLiveURL(%q): %v", tc.in, err)
			continue
		}
		if got.Shown != tc.shown || got.Host != tc.host || got.Port != tc.port || got.Path != tc.path {
			t.Errorf("ParseLiveURL(%q) = %+v, want %+v", tc.in, got, tc)
		}
	}
	for _, in := range []string{"", "https://", "https://user:pw@app.example.com", "gopher://app.example.com", "https://app.example.com:0", "http://app example.com"} {
		if got, err := ParseLiveURL(in); err == nil {
			t.Errorf("ParseLiveURL(%q) = %+v, want an error", in, got)
		} else if strings.Contains(err.Error(), "pw") {
			t.Errorf("ParseLiveURL(%q) repeats the password: %v", in, err)
		}
	}
}
