package euvd

import (
	"os"
	"slices"
	"testing"

	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/kev"
)

// TestRulesMatchENISAOnlyFlaws checks which of Hejnal's products the flaws
// only ENISA lists map to, with ENISA's own spelling of their names.
func TestRulesMatchENISAOnlyFlaws(t *testing.T) {
	eng, err := fingerprint.Default()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Load(dumpSample)
	if err != nil {
		t.Fatal(err)
	}
	// Two flaws ENISA describes as affecting "Various" products: one with
	// no record and one whose description names FortiWeb.
	entries = append(entries,
		Entry{CVEID: "CVE-2026-1", EUVDID: "EUVD-2026-1", VendorProject: "Fortinet", Product: "Various", DateAdded: "2026-11-01", Sources: []string{SourceENISA}},
		Entry{CVEID: "CVE-2026-2", EUVDID: "EUVD-2026-2", VendorProject: "Fortinet", Product: "Various", DateAdded: "2026-11-01", Sources: []string{SourceENISA}},
	)
	f, err := os.Open(recordSample)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := ParseRecord(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]*Record{
		rec.ID:        rec,
		"EUVD-2026-2": {ID: "EUVD-2026-2", Description: "A path traversal in FortiWeb lets attackers run commands."},
	}
	cat := &kev.Catalog{Vulnerabilities: []kev.Vulnerability{{CVEID: "CVE-2000-0001", VendorProject: "x", Product: "y"}}}
	Merge(cat, entries, records)

	want := map[string][]string{
		"CVE-2026-67276": {"mikrotik-routeros", "mikrotik-routeros-services"}, // MikroTik RouterOS
		"CVE-2025-59719": {"fortinet-fortiweb"},                               // "Fortiweb"
		"CVE-2026-85103": {"checkpoint"},                                      // Check Point Quantum
		"CVE-2015-0279":  {"richfaces"},                                       // JBoss RichFaces
		"CVE-2023-3519":  {"citrix-netscaler"},                                // "Citrix ADC and Citrix Gateway"
		"CVE-2026-74232": nil,                                                 // Zbtlink "Various"
		"CVE-2026-40477": nil,                                                 // Thymeleaf, a library
		"CVE-2026-1":     nil,                                                 // "Various" on its own
		"CVE-2026-2":     {"fortinet-fortiweb"},                               // "Various", described as FortiWeb
	}
	for _, v := range cat.Vulnerabilities {
		w, ok := want[v.CVEID]
		if !ok {
			continue
		}
		delete(want, v.CVEID)
		var got []string
		for _, r := range eng.Rules() {
			if eng.MatchesKEV(r.ID, v.VendorProject, v.Product, v.VulnerabilityName+" "+v.ShortDescription) {
				got = append(got, r.ID)
			}
		}
		if !slices.Equal(got, w) {
			t.Errorf("%s (%s | %s) matches %v, want %v", v.CVEID, v.VendorProject, v.Product, got, w)
		}
	}
	for cve := range want {
		t.Errorf("%s was not added", cve)
	}
}
