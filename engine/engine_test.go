package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/leaks"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func TestRunWithVersionChecks(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
		io.WriteString(w, `<html><head><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	}))
	defer site.Close()
	// A stand-in for NVD's API serving the real records in nvd/testdata.
	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(filepath.Join("..", "nvd", "testdata", filepath.Base(r.URL.Query().Get("cveId"))+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	defer nvdSrv.Close()

	u, _ := url.Parse(site.URL)
	port, _ := strconv.Atoi(u.Port())
	s := &scope.Scope{
		Organization:  "Test",
		Authorization: scope.Authorization{ConfirmedBy: "Test", Date: "2026-11-01", Statement: "Test."},
		Hosts:         []string{"127.0.0.1"},
		Ports:         []int{port},
	}
	if err := s.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Config{
		StateDir: dir,
		KEVFile:  "../testdata/kev_sample.json",
		NoEPSS:   true,
		NoCT:     true,
		NVDURL:   nvdSrv.URL,
		Timeout:  3 * time.Second,
		Now:      func() time.Time { return testNow },
		nvdPause: time.Millisecond,
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	check := func(fs []match.Finding) {
		t.Helper()
		got := map[string]string{}
		for _, f := range fs {
			got[f.CVE] = f.Confidence
		}
		for cve, want := range map[string]string{
			"CVE-2026-109618": match.ConfidenceVersion,  // PHP 8.3.12 is below 8.3.36
			"CVE-2024-4577":   match.ConfidenceRuledOut, // fixed in 8.3.8
			"CVE-2026-119977": match.ConfidenceVersion,  // WordPress 6.8.1 is affected
			"CVE-2026-87902":  match.ConfidenceProduct,  // no NVD record: unknown
		} {
			if got[cve] != want {
				t.Errorf("%s confidence = %q, want %q", cve, got[cve], want)
			}
		}
	}
	check(res.Snapshot.Findings)
	for _, f := range res.Changes.Added {
		if f.RuledOut() {
			t.Errorf("ruled-out flaw %s reported as new", f.CVE)
		}
	}
	if res.Snapshot.Services != 1 || res.Snapshot.Technologies != 2 {
		t.Errorf("snapshot counts = %d services, %d technologies", res.Snapshot.Services, res.Snapshot.Technologies)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache", "nvd", "CVE-2026-109618.json")); err != nil {
		t.Errorf("NVD record not cached: %v", err)
	}

	// Offline, the cached records give the same answers without NVD.
	nvdSrv.Close()
	cfg.Offline = true
	e2, _ := New(cfg)
	snap, err := e2.Match(context.Background(), res.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	check(snap.Findings)
}

func TestNewRequiresStateDir(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New accepted an empty state directory")
	}
}

func TestMatchIncludesSavedLeaks(t *testing.T) {
	dir := t.TempDir()
	e, err := New(Config{StateDir: dir, KEVFile: "../testdata/kev_sample.json", NoEPSS: true, NoCT: true, NoNVD: true,
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	store := e.Store()
	if err := store.SaveLeakScan(&state.LeakScan{ScannedAt: testNow, Leaks: []leaks.Leak{{RuleID: "aws-access-key-id",
		Description: "AWS access key ID", Severity: "critical", File: "web/deploy.sh", Line: 7,
		Redacted: "AKIA… (20 chars)", Fingerprint: "0011223344556677"}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBreachCheck(&state.BreachCheck{CheckedAt: testNow, Domains: []leaks.DomainSummary{{Domain: "example.com",
		Accounts: 1, Breaches: []leaks.DomainBreach{{Name: "Adobe", Title: "Adobe", BreachDate: "2013-10-04", Accounts: 1, Passwords: true}}}}}); err != nil {
		t.Fatal(err)
	}
	snap, err := e.Match(context.Background(), &inventory.Inventory{Organization: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[match.Kind]int{}
	for _, f := range snap.Findings {
		kinds[f.Kind]++
	}
	if kinds[match.KindSecret] != 1 || kinds[match.KindBreach] != 1 {
		t.Errorf("finding kinds = %v", kinds)
	}
	if snap.Findings[0].Kind != match.KindSecret {
		t.Errorf("the critical secret should come first, got %+v", snap.Findings[0])
	}
}

func TestChangesComparesActiveFindings(t *testing.T) {
	e, err := New(Config{StateDir: t.TempDir(), NoEPSS: true, NoCT: true, NoNVD: true})
	if err != nil {
		t.Fatal(err)
	}
	ruledOut := match.Finding{Key: "kev|w|443|CVE-2021-41773", Kind: match.KindKEV, Host: "w", Port: 443, CVE: "CVE-2021-41773",
		Version: "2.4.62", Score: 20, Severity: match.Low, Confidence: match.ConfidenceRuledOut}
	if err := e.MarkReported(&state.Snapshot{Findings: []match.Finding{ruledOut}}); err != nil {
		t.Fatal(err)
	}
	// The server stops showing its version, so the flaw is active again.
	active := ruledOut
	active.Version, active.Score, active.Severity, active.Confidence = "", 80, match.High, match.ConfidenceProduct
	ch, err := e.Changes(&state.Snapshot{Findings: []match.Finding{active}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 1 || len(ch.Resolved) != 0 {
		t.Errorf("flaw active again: added %d, resolved %d; want 1 and 0", len(ch.Added), len(ch.Resolved))
	}
	// And the other way round: ruled out after an update counts as resolved.
	if err := e.MarkReported(&state.Snapshot{Findings: []match.Finding{active}}); err != nil {
		t.Fatal(err)
	}
	ch, err = e.Changes(&state.Snapshot{Findings: []match.Finding{ruledOut}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Added) != 0 || len(ch.Resolved) != 1 {
		t.Errorf("flaw ruled out: added %d, resolved %d; want 0 and 1", len(ch.Added), len(ch.Resolved))
	}
}
