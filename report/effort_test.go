package report

import (
	"strings"
	"testing"

	"github.com/Legatia/hejnal/match"
)

func TestFixOrder(t *testing.T) {
	fs := []match.Finding{
		{Kind: match.KindKEV, Key: "k1", Host: "vpn.example.com", Port: 443, TechID: "fortigate", Technology: "FortiGate", Category: "edge", CVE: "CVE-1", Score: 95, Severity: match.Critical, Confidence: match.ConfidenceProduct},
		{Kind: match.KindKEV, Key: "k2", Host: "www.example.com", Port: 443, TechID: "wordpress", Technology: "WordPress", Category: "cms", CVE: "CVE-2", Score: 75, Severity: match.High, Confidence: match.ConfidenceProduct},
		{Kind: match.KindEmail, Key: "e1", Host: "example.com", TechID: "dmarc-none", Score: 40, Severity: match.Medium},
		{Kind: match.KindEmail, Key: "e2", Host: "example.com", TechID: "spf-missing", Score: 55, Severity: match.Medium},
		{Kind: match.KindExposedFile, Key: "x1", Host: "files.example.com", Port: 443, TechID: "directory-listing", Score: 45, Severity: match.Medium},
		{Kind: match.KindExposedFile, Key: "x2", Host: "www.example.com", Port: 443, TechID: "server-status", Score: 50, Severity: match.Medium},
	}
	first, quick := FixOrder(match.Groups(fs))
	if len(first) != 2 || first[0].Key != "fortigate|vpn.example.com:443" && first[0].Technology != "FortiGate" {
		t.Errorf("first = %+v", first)
	}
	var q []string
	for _, g := range quick {
		q = append(q, g.TechID)
	}
	// 15-minute items first, by score, then the 30-minute SPF record.
	if strings.Join(q, " ") != "server-status directory-listing dmarc-none spf-missing" {
		t.Errorf("quick = %v", q)
	}
	if Effort(first[0]) != 240 || Effort(first[1]) != 120 {
		t.Errorf("efforts %d %d", Effort(first[0]), Effort(first[1]))
	}

	var b strings.Builder
	if err := FixList(&b, fs, Meta{Organization: "Acme", Lang: "en", Services: 4}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"## Where to start", "- 1. FortiGate on vpn.example.com:443: CVE-1 · about half a day", "That is about 6 hours of work in all.", "**Quick wins: 30 minutes or less each**", "- **Rough effort:** about two hours"} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list lacks %q", want)
		}
	}
	if strings.Index(out, "## Where to start") > strings.Index(out, "### 1.") {
		t.Error("where to start comes after the list")
	}
	if strings.Contains(out, "ENISA lists") {
		t.Error("a finding without lists was credited to ENISA")
	}
}
