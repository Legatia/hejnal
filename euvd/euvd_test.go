package euvd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/kev"
)

const dumpSample = "../testdata/euvd_kev_sample.json"
const recordSample = "../testdata/euvd_record_EUVD-2026-72024.json"

func TestParseRealDump(t *testing.T) {
	entries, err := Load(dumpSample)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 29 {
		t.Fatalf("got %d entries, want 29", len(entries))
	}
	var mikrotik Entry
	enisaOnly := 0
	for _, e := range entries {
		if e.CVEID == "CVE-2026-67276" {
			mikrotik = e
		}
		if e.ENISA() && !slices.Contains(e.Sources, SourceCISA) {
			enisaOnly++
		}
	}
	want := Entry{CVEID: "CVE-2026-67276", EUVDID: "EUVD-2026-72024", VendorProject: "MikroTik", Product: "RouterOS",
		VulnerabilityName: "MikroTrick", DateAdded: "2026-09-05", Sources: []string{SourceENISA}}
	if !equalEntry(mikrotik, want) {
		t.Errorf("MikroTik entry = %+v, want %+v", mikrotik, want)
	}
	if enisaOnly != 6 {
		t.Errorf("%d entries only ENISA lists, want 6", enisaOnly)
	}
}

func equalEntry(a, b Entry) bool {
	return a.CVEID == b.CVEID && a.EUVDID == b.EUVDID && a.VendorProject == b.VendorProject && a.Product == b.Product &&
		a.VulnerabilityName == b.VulnerabilityName && a.DateAdded == b.DateAdded && slices.Equal(a.Sources, b.Sources)
}

func TestParseDropsMalformedEntries(t *testing.T) {
	in := `[
	 {"cveId":"CVE-2026-1234","euvdId":"EUVD-2026-1","dateAdded":"2026-01-02","sources":["cisa_kev","other"]},
	 {"cveId":"CVE-2026-1234](x)","euvdId":"EUVD-2026-2","dateAdded":"2026-01-02","sources":["eukev_kev"]},
	 {"cveId":"CVE-2026-1235","euvdId":"EUVD-2026-3<b>","dateAdded":"2026-01-02","sources":["eukev_kev"]},
	 {"cveId":"CVE-2026-1236","euvdId":"EUVD-2026-4","dateAdded":"Jan 2, 2026","sources":["eukev_kev"]},
	 {"cveId":" cve-2026-1237 ","euvdId":"EUVD-2026-5","dateAdded":"2026-01-02","sources":["eukev_kev"],
	  "vendorProject":" Acme Corp\n","product":"Widget\u0007Server"}
	]`
	entries, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("kept %d entries, want 2: %+v", len(entries), entries)
	}
	if !slices.Equal(entries[0].Sources, []string{SourceCISA}) {
		t.Errorf("unknown source kept: %v", entries[0].Sources)
	}
	if e := entries[1]; e.CVEID != "CVE-2026-1237" || e.VendorProject != "Acme Corp" || e.Product != "Widget Server" {
		t.Errorf("not normalised: %+v", e)
	}
	if _, err := Parse(strings.NewReader(`[]`)); err == nil {
		t.Error("an empty list should be an error")
	}
	if _, err := Parse(strings.NewReader(`{"error":"x"}`)); err == nil {
		t.Error("an object should be an error")
	}
}

func TestParseRealRecord(t *testing.T) {
	f, err := os.Open(recordSample)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rec, err := ParseRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != "EUVD-2026-72024" {
		t.Errorf("ID = %q", rec.ID)
	}
	if !strings.HasPrefix(rec.Description, "RouterOS does not compare the complete RSA public key") ||
		strings.Contains(rec.Description, " ") {
		t.Errorf("description = %q", rec.Description)
	}
	if len(rec.References) != 6 || rec.References[0] != "https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve" {
		t.Errorf("references = %q", rec.References)
	}
	want := []Product{{"MikroTik", "RouterOS", "7.24 <7.24.2"}, {"MikroTik", "RouterOS", "7.9 <7.23.4"}}
	if !slices.Equal(rec.Products, want) {
		t.Errorf("products = %+v, want %+v", rec.Products, want)
	}
}

func TestParseRecordFiltersReferences(t *testing.T) {
	rec, err := ParseRecord(strings.NewReader(`{"id":"EUVD-2026-9","references":"javascript:alert(1)\nhttps://ok.example/a\nhttps://bad.example/a\"><img src=x>\nhttps://ok.example/a\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rec.References, []string{"https://ok.example/a"}) {
		t.Errorf("references = %q", rec.References)
	}
	if _, err := ParseRecord(strings.NewReader(`{"id":"CVE-2026-1"}`)); err == nil {
		t.Error("a record without an EUVD ID should be an error")
	}
}

func TestFetch(t *testing.T) {
	dump, err := os.ReadFile(dumpSample)
	if err != nil {
		t.Fatal(err)
	}
	record, err := os.ReadFile(recordSample)
	if err != nil {
		t.Fatal(err)
	}
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		switch {
		case r.URL.Path == "/api/kev/dump":
			w.Write(dump)
		case r.URL.Path == "/api/enisaid" && r.URL.Query().Get("id") == "EUVD-2026-72024":
			w.Write(record)
		case r.URL.Path == "/api/enisaid":
			// ENISA's real answer for an unknown ID.
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"EUVD not found"}`))
		default:
			http.Error(w, "nope", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	dest := filepath.Join(t.TempDir(), "cache", "euvd-kev.json")

	entries, err := Fetch(ctx, srv.Client(), srv.URL+"/api/kev/dump", "hejnal-test", dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 29 || ua != "hejnal-test" {
		t.Fatalf("got %d entries with user agent %q", len(entries), ua)
	}
	if saved, err := Load(dest); err != nil || len(saved) != 29 {
		t.Fatalf("saved copy: %d entries, %v", len(saved), err)
	}
	if _, err := Fetch(ctx, srv.Client(), srv.URL+"/broken", "hejnal-test", dest); err == nil {
		t.Error("a failed download should be an error")
	}
	if saved, err := Load(dest); err != nil || len(saved) != 29 {
		t.Errorf("a failed download damaged the saved copy: %v", err)
	}

	rec, err := FetchRecord(ctx, srv.Client(), srv.URL+"/api/enisaid", "hejnal-test", "EUVD-2026-72024")
	if err != nil || rec.ID != "EUVD-2026-72024" {
		t.Fatalf("record %+v, %v", rec, err)
	}
	if _, err := FetchRecord(ctx, srv.Client(), srv.URL+"/api/enisaid", "hejnal-test", "EUVD-2026-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown ID: %v, want ErrNotFound", err)
	}
	if _, err := FetchRecord(ctx, srv.Client(), srv.URL+"/api/enisaid", "hejnal-test", "EUVD-1&x=y"); err == nil {
		t.Error("an invalid ID should be refused before asking")
	}
}

func TestCache(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rec := &Record{ID: "EUVD-2026-72024", Description: "d", References: []string{"https://a.example"}}
	if err := c.Put(rec, now); err != nil {
		t.Fatal(err)
	}
	got, fetched, ok := c.Get("EUVD-2026-72024")
	if !ok || got.Description != "d" || !fetched.Equal(now) {
		t.Errorf("Get = %+v, %v, %v", got, fetched, ok)
	}
	if _, _, ok := c.Get("../x"); ok {
		t.Error("an invalid ID should not be read")
	}
	if err := c.Put(&Record{ID: "../x"}, now); err == nil {
		t.Error("an invalid ID should not be written")
	}
}

func TestPublished(t *testing.T) {
	for _, c := range []struct{ now, want string }{
		{"2026-11-07T06:59:00Z", "2026-11-06T07:00:00Z"},
		{"2026-11-07T07:00:00Z", "2026-11-07T07:00:00Z"},
		{"2026-11-07T23:00:00+02:00", "2026-11-07T07:00:00Z"},
		{"2026-11-07T01:00:00+02:00", "2026-11-06T07:00:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, c.now)
		if got := Published(now).Format(time.RFC3339); got != c.want {
			t.Errorf("Published(%s) = %s, want %s", c.now, got, c.want)
		}
	}
}

func TestMerge(t *testing.T) {
	cat, err := kev.Load("../testdata/kev_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	cisa := len(cat.Vulnerabilities)
	entries, err := Load(dumpSample)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(recordSample)
	rec, err := ParseRecord(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Six flaws only ENISA lists, and CVE-2023-3519, which both list but
	// this sample of CISA's catalog leaves out.
	only := ENISAOnly(cat, entries)
	if len(only) != 7 {
		t.Fatalf("%d entries only ENISA lists, want 7", len(only))
	}
	st := Merge(cat, entries, map[string]*Record{rec.ID: rec})
	if st.IDs != cisa+7 || st.ENISAOnly != 7 || st.Earlier != 2 {
		t.Errorf("stats = %+v, want %d IDs, 7 ENISA-only, 2 earlier", st, cisa+7)
	}
	byCVE := map[string]kev.Vulnerability{}
	for _, v := range cat.Vulnerabilities {
		byCVE[v.CVEID] = v
	}

	// ENISA listed these before CISA did.
	for cve, date := range map[string]string{"CVE-2026-96951": "2026-09-25", "CVE-2026-87902": "2026-09-23"} {
		v := byCVE[cve]
		if !v.ENISA || v.ENISAOnly || v.ENISAEarlier != date || v.DateAdded <= date {
			t.Errorf("%s: %+v, want ENISA earlier on %s", cve, v, date)
		}
	}
	if v := byCVE["CVE-2021-26855"]; v.EUVDID != "EUVD-2021-13639" || v.ENISA || v.ENISAEarlier != "" {
		t.Errorf("CISA-only flaw: %+v", v)
	}

	m := byCVE["CVE-2026-67276"]
	if !m.ENISAOnly || m.VendorProject != "MikroTik" || m.Product != "RouterOS" || m.DateAdded != "2026-09-05" ||
		m.VulnerabilityName != "MikroTik RouterOS vulnerability (MikroTrick)" || m.RequiredAction != "" || m.DueDate != "" {
		t.Errorf("MikroTik: %+v", m)
	}
	if !strings.Contains(m.ShortDescription, "SSH authentication") || len(m.Links()) != 6 {
		t.Errorf("MikroTik record not used: %q, %v", m.ShortDescription, m.Links())
	}
	if z := byCVE["CVE-2026-74232"]; z.Product != "Multiple Products" || z.VulnerabilityName != "Zbtlink products vulnerability" {
		t.Errorf("Zbtlink: %+v", z)
	}
	if fw := byCVE["CVE-2025-59719"]; fw.ShortDescription != "" || fw.Notes != "" {
		t.Errorf("FortiWeb without a record: %+v", fw)
	}
	// Marked as CISA's in the dump but not in CISA's catalog: withdrawn.
	if _, ok := byCVE["CVE-2026-69836"]; ok {
		t.Error("a flaw CISA no longer lists was added")
	}

	n := len(cat.Vulnerabilities)
	if st := Merge(cat, entries, nil); len(cat.Vulnerabilities) != n || st != (Stats{}) {
		t.Errorf("merging twice changed the catalog: %+v", st)
	}
	if len(ENISAOnly(cat, entries)) != 7 {
		t.Error("ENISAOnly should still list the added flaws")
	}
}
