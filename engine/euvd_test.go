package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/match"
)

// feedServer stands in for CISA's feed and ENISA's EUVD API, serving the
// real samples in testdata and counting requests.
type feedServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests map[string]int
	failEUVD bool
}

func newFeedServer(t *testing.T) *feedServer {
	t.Helper()
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	kevData, dump, record := read("kev_sample.json"), read("euvd_kev_sample.json"), read("euvd_record_EUVD-2026-72024.json")
	fs := &feedServer{requests: map[string]int{}}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		key := r.URL.Path
		if id := r.URL.Query().Get("id"); id != "" {
			key += "?" + id
		}
		fs.requests[key]++
		fail := fs.failEUVD
		fs.mu.Unlock()
		switch {
		case r.URL.Path == "/kev.json":
			w.Write(kevData)
		case fail:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case r.URL.Path == "/api/kev/dump":
			w.Write(dump)
		case r.URL.Path == "/api/enisaid" && r.URL.Query().Get("id") == "EUVD-2026-72024":
			w.Write(record)
		case r.URL.Path == "/api/enisaid":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"EUVD not found"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *feedServer) setFailEUVD(fail bool) {
	fs.mu.Lock()
	fs.failEUVD = fail
	fs.mu.Unlock()
}

func (fs *feedServer) count(prefix string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for k, v := range fs.requests {
		if strings.HasPrefix(k, prefix) {
			n += v
		}
	}
	return n
}

func (fs *feedServer) config(dir string, logs *[]string) Config {
	return Config{
		StateDir:      dir,
		KEVURL:        fs.URL + "/kev.json",
		EUVDURL:       fs.URL + "/api/kev/dump",
		EUVDRecordURL: fs.URL + "/api/enisaid",
		NoEPSS:        true,
		NoCT:          true,
		NoNVD:         true,
		HTTPClient:    fs.Client(),
		Now:           func() time.Time { return testNow },
		Logf:          func(f string, a ...any) { *logs = append(*logs, fmt.Sprintf(f, a...)) },
	}
}

func byCVE(cat *kev.Catalog) map[string]kev.Vulnerability {
	out := map[string]kev.Vulnerability{}
	for _, v := range cat.Vulnerabilities {
		out[v.CVEID] = v
	}
	return out
}

func TestCatalogAddsENISAList(t *testing.T) {
	srv := newFeedServer(t)
	dir := t.TempDir()
	var logs []string
	e, err := New(srv.config(dir, &logs))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := e.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cat.EUVDDate != time.Now().UTC().Add(-7*time.Hour).Format("2006-01-02") {
		t.Errorf("EUVD date = %q", cat.EUVDDate)
	}
	v := byCVE(cat)
	if m := v["CVE-2026-67276"]; !m.ENISAOnly || m.EUVDID != "EUVD-2026-72024" || !strings.Contains(m.ShortDescription, "RouterOS") {
		t.Errorf("MikroTik flaw only ENISA lists: %+v", m)
	}
	if w := v["CVE-2026-87902"]; w.ENISAEarlier != "2026-09-23" || w.EUVDID != "EUVD-2026-84555" {
		t.Errorf("WordPress flaw ENISA listed first: %+v", w)
	}
	// One request for the list, and one record for each of the 7 flaws
	// that are not in the sample of CISA's catalog.
	if n, r := srv.count("/api/kev/dump"), srv.count("/api/enisaid"); n != 1 || r != 7 {
		t.Errorf("%d list and %d record requests, want 1 and 7", n, r)
	}
	if !slices.ContainsFunc(logs, func(l string) bool { return strings.Contains(l, "ENISA's list of exploited vulnerabilities (29 flaws") }) {
		t.Errorf("download not logged: %q", logs)
	}

	// The saved list is current until ENISA publishes the next one, and
	// records found are kept; records ENISA does not have are asked again.
	if _, err := e.Catalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, r := srv.count("/api/kev/dump"), srv.count("/api/enisaid?EUVD-2026-72024"); n != 1 || r != 1 {
		t.Errorf("second run downloaded the list %d times and the record %d times, want once each", n, r)
	}

	// The findings say which lists include each flaw.
	inv := &inventory.Inventory{Organization: "Test", Assets: []inventory.Asset{{Host: "gw.example.com", Services: []inventory.Service{{
		Port: 8291, Technologies: []inventory.Technology{{ID: "mikrotik-routeros-services", Name: "MikroTik RouterOS", Category: "network"}},
	}}}}}
	snap, err := e.MatchCatalog(context.Background(), inv, cat)
	if err != nil {
		t.Fatal(err)
	}
	var found *match.Finding
	for i, f := range snap.Findings {
		if f.CVE == "CVE-2026-67276" {
			found = &snap.Findings[i]
		}
	}
	if found == nil || !found.ENISAOnly() || found.EUVD != "EUVD-2026-72024" || len(found.Links) != 6 || found.Description == "" {
		t.Fatalf("finding for the flaw only ENISA lists: %+v\nall: %+v", found, snap.Findings)
	}
	if snap.EUVDDate != cat.EUVDDate {
		t.Errorf("snapshot EUVD date = %q, want %q", snap.EUVDDate, cat.EUVDDate)
	}

	// Offline, the saved copies are used and nothing is downloaded.
	before := srv.count("/")
	srv.setFailEUVD(true)
	cfg := srv.config(dir, &logs)
	cfg.Offline = true
	off, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cat, err = off.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := byCVE(cat)["CVE-2026-67276"]; !m.ENISAOnly || m.ShortDescription == "" {
		t.Errorf("offline: %+v", m)
	}
	if after := srv.count("/"); after != before {
		t.Errorf("offline run made %d requests", after-before)
	}
}

func TestCatalogWithoutENISAList(t *testing.T) {
	srv := newFeedServer(t)
	srv.setFailEUVD(true)
	var logs []string
	e, err := New(srv.config(t.TempDir(), &logs))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := e.Catalog(context.Background())
	if err != nil {
		t.Fatalf("an unavailable ENISA list should not stop the run: %v", err)
	}
	if cat.EUVDDate != "" || len(cat.Vulnerabilities) != 21 {
		t.Errorf("catalog: EUVD date %q, %d flaws", cat.EUVDDate, len(cat.Vulnerabilities))
	}
	if !slices.ContainsFunc(logs, func(l string) bool { return strings.Contains(l, "using CISA's catalog alone") }) {
		t.Errorf("missing list not logged: %q", logs)
	}

	// With -no-euvd, ENISA is not asked at all.
	srv2 := newFeedServer(t)
	cfg := srv2.config(t.TempDir(), &logs)
	cfg.NoEUVD = true
	e, _ = New(cfg)
	if _, err := e.Catalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := srv2.count("/api/"); n != 0 {
		t.Errorf("-no-euvd made %d requests to ENISA", n)
	}

	// Reading CISA's catalog from a file downloads nothing from ENISA, and
	// a missing saved list is not worth a warning.
	srv3 := newFeedServer(t)
	logs = nil
	cfg = srv3.config(t.TempDir(), &logs)
	cfg.KEVFile = "../testdata/kev_sample.json"
	e, _ = New(cfg)
	if _, err := e.Catalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := srv3.count("/"); n != 0 || len(logs) != 0 {
		t.Errorf("with a KEV file: %d requests, logs %q", n, logs)
	}
	// ...and an EUVD file is used as given.
	cfg.EUVDFile = "../testdata/euvd_kev_sample.json"
	e, _ = New(cfg)
	cat, err = e.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := byCVE(cat)["CVE-2026-67276"]; !m.ENISAOnly || m.ShortDescription != "" {
		t.Errorf("from files: %+v", m)
	}
	if n := srv3.count("/"); n != 0 {
		t.Errorf("with files: %d requests", n)
	}
}
