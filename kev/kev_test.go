package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = "../testdata/kev_sample.json"

func find(t *testing.T, c *Catalog, id string) Vulnerability {
	t.Helper()
	for _, v := range c.Vulnerabilities {
		if v.CVEID == id {
			return v
		}
	}
	t.Fatalf("%s not in catalog", id)
	return Vulnerability{}
}

func TestLoadSample(t *testing.T) {
	cat, err := Load(sample)
	if err != nil {
		t.Fatal(err)
	}
	if cat.CatalogVersion != "2026.11.03" {
		t.Errorf("CatalogVersion = %q", cat.CatalogVersion)
	}
	if len(cat.Vulnerabilities) != 21 {
		t.Errorf("got %d vulnerabilities, want 21", len(cat.Vulnerabilities))
	}

	wp := find(t, cat, "CVE-2026-119977")
	if !wp.Forensics() || wp.Ransomware() {
		t.Errorf("CVE-2026-119977: forensics %v ransomware %v, want true false", wp.Forensics(), wp.Ransomware())
	}
	if added, ok := wp.Added(); !ok || !added.Equal(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Added() = %v %v", added, ok)
	}
	links := wp.Links()
	if len(links) < 2 || !strings.HasPrefix(links[0], "https://wordpress.org/") {
		t.Fatalf("Links() = %v, want the vendor advisory first", links)
	}
	if last := links[len(links)-1]; !strings.Contains(last, "cisa.gov/news-events/directives") {
		t.Errorf("last link = %q, want CISA's directive pages last", last)
	}

	if !find(t, cat, "CVE-2018-13379").Ransomware() {
		t.Error("CVE-2018-13379 is linked to ransomware")
	}
}

func TestParseNormalises(t *testing.T) {
	doc := `{"catalogVersion": "x", "vulnerabilities": [{"cveID": " cve-2026-0001 ", "vendorProject": "Ivanti",
		"product": " Endpoint Manager  (EPM)", "dateAdded": " 2026-01-02 "}]}`
	cat, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	v := cat.Vulnerabilities[0]
	if v.CVEID != "CVE-2026-0001" || v.Product != "Endpoint Manager (EPM)" || v.DateAdded != "2026-01-02" {
		t.Errorf("got %+v", v)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	for _, doc := range []string{`{"vulnerabilities": []}`, `not json`} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("Parse(%q) succeeded", doc)
		}
	}
}

func TestFetch(t *testing.T) {
	data, err := os.ReadFile(sample)
	if err != nil {
		t.Fatal(err)
	}
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		w.Write(data)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "cache", "kev.json")
	cat, err := Fetch(context.Background(), srv.Client(), srv.URL, "hejnal-test", dest)
	if err != nil {
		t.Fatal(err)
	}
	if gotUA != "hejnal-test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if len(cat.Vulnerabilities) != 21 {
		t.Errorf("got %d vulnerabilities", len(cat.Vulnerabilities))
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("cache mode = %v, want 0600", fi.Mode().Perm())
	}

	// A failed download must leave the cached copy alone.
	for _, h := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusBadGateway) },
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"vulnerabilities": [`)) },
	} {
		bad := httptest.NewServer(h)
		if _, err := Fetch(context.Background(), bad.Client(), bad.URL, "hejnal-test", dest); err == nil {
			t.Error("Fetch succeeded on a bad response")
		}
		bad.Close()
		if cached, err := Load(dest); err != nil || len(cached.Vulnerabilities) != 21 {
			t.Errorf("cache damaged after failed download: %v", err)
		}
	}
}
