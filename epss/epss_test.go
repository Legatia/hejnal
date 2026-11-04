package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Scores below are made up; they only exercise the API format.
const apiSample = `{"status": "OK", "status-code": 200, "version": "1.0", "total": 2, "data": [
  {"cve": "CVE-2026-0001", "epss": "0.912340000", "percentile": "0.998760000", "date": "2026-11-03"},
  {"cve": "cve-2026-0002", "epss": 0.0123, "percentile": 0.5, "date": "2026-11-03"}
]}`

func TestParseResponse(t *testing.T) {
	scores, err := ParseResponse(strings.NewReader(apiSample))
	if err != nil {
		t.Fatal(err)
	}
	if s := scores["CVE-2026-0001"]; s.EPSS != 0.91234 || s.Percentile != 0.99876 || s.Date != "2026-11-03" {
		t.Errorf("CVE-2026-0001 = %+v", s)
	}
	if s, ok := scores["CVE-2026-0002"]; !ok || s.EPSS != 0.0123 {
		t.Errorf("CVE-2026-0002 = %+v %v (want numbers accepted and the ID upper-cased)", s, ok)
	}
}

func TestParseResponseClampsScores(t *testing.T) {
	scores, err := ParseResponse(strings.NewReader(`{"data": [{"cve": "CVE-2026-0003", "epss": "-3", "percentile": "7", "date": "2026-11-03](https://evil.example)"}, {"cve": "CVE-1](x)", "epss": "0.5"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := scores["CVE-2026-0003"]; s.EPSS != 0 || s.Percentile != 1 || s.Date != "" {
		t.Errorf("got %+v, want scores clamped to 0–1 and the malformed date cleared", s)
	}
	if len(scores) != 1 {
		t.Errorf("an entry with an invalid CVE ID was kept: %v", scores)
	}
}

func TestParseResponseErrors(t *testing.T) {
	for _, doc := range []string{
		`{"status": "error", "data": []}`,
		`{"data": [{"cve": "x", "epss": "abc"}]}`,
		`{"data": [{"cve": "x", "epss": "NaN"}]}`,
		`{"data": [{"cve": "x", "epss": "+Inf"}]}`,
		`<html>`,
	} {
		if _, err := ParseResponse(strings.NewReader(doc)); err == nil {
			t.Errorf("ParseResponse(%q) succeeded", doc)
		}
	}
}

func TestFetchBatches(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var data []map[string]string
		for _, c := range strings.Split(r.URL.Query().Get("cve"), ",") {
			data = append(data, map[string]string{"cve": c, "epss": "0.5", "percentile": "0.9", "date": "2026-11-03"})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "OK", "data": data})
	}))
	defer srv.Close()

	var cves []string
	for i := 0; i < 250; i++ {
		cves = append(cves, fmt.Sprintf("CVE-2026-%04d", i))
	}
	cves = append(cves, cves[0]) // duplicates are sent once
	scores, err := Fetch(context.Background(), srv.Client(), srv.URL, "hejnal-test", cves)
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 250 {
		t.Errorf("got %d scores, want 250", len(scores))
	}
	if n := requests.Load(); n != 3 {
		t.Errorf("made %d requests, want 3 batches of up to %d", n, batchSize)
	}
}

func TestFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, "hejnal-test", []string{"CVE-2026-0001"}); err == nil {
		t.Fatal("Fetch succeeded on HTTP 429")
	}
}

func TestCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache", "epss.json")
	empty, err := LoadCache(path)
	if err != nil || len(empty) != 0 {
		t.Fatalf("LoadCache on a missing file = %v, %v", empty, err)
	}
	want := map[string]Score{"CVE-2026-0001": {CVE: "CVE-2026-0001", EPSS: 0.25, Percentile: 0.8, Date: "2026-11-03"}}
	if err := SaveCache(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2026-0001"] != want["CVE-2026-0001"] {
		t.Errorf("round trip = %+v", got)
	}
}
