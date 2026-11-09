package report

import (
	"strings"
	"testing"

	"github.com/Legatia/hejnal/match"
)

func kevGroup(fs ...match.Finding) match.Group {
	for i := range fs {
		fs[i].Kind, fs[i].Host, fs[i].Port = match.KindKEV, "vpn.example.com", 443
		fs[i].URL, fs[i].Technology, fs[i].TechID = "https://vpn.example.com/remote/login", "FortiGate SSL VPN", "fortigate"
		fs[i].Evidence = "login page /remote/login"
		if fs[i].ListedBy == nil {
			fs[i].ListedBy = []string{match.ListCISA}
		}
	}
	return match.Groups(fs)[0]
}

func TestProof(t *testing.T) {
	confirmed := kevGroup(match.Finding{CVE: "CVE-2024-21762", Version: "7.2.4", Confidence: match.ConfidenceVersion, DateAdded: "2024-02-09", Score: 90})
	p := ProofOf(confirmed, "en")
	if p.Verdict != VerdictConfirmed || len(p.Steps) != 4 || !strings.Contains(p.Steps[2].Text, "CVE-2024-21762") || !strings.Contains(p.Steps[3].Text, "2024-02-09") {
		t.Errorf("confirmed: %+v", p)
	}
	if p.Command != "curl -sk -D - -o /dev/null 'https://vpn.example.com/remote/login'" {
		t.Errorf("command = %q", p.Command)
	}
	for _, s := range p.Steps {
		if !s.OK {
			t.Errorf("an unchecked step in a confirmed item: %+v", s)
		}
	}

	noVersion := kevGroup(match.Finding{CVE: "CVE-2024-21762", Confidence: match.ConfidenceProduct, ListedBy: []string{match.ListCISA, match.ListENISA}, DateAdded: "2024-02-09"})
	if p := ProofOf(noVersion, "en"); p.Verdict != VerdictLikely || p.Steps[1].OK || !strings.Contains(p.Steps[2].Text, "ENISA") {
		t.Errorf("no version: %+v", p)
	}
	packaged := kevGroup(match.Finding{CVE: "CVE-2023-38408", Version: "8.9p1", Packaged: true, Confidence: match.ConfidenceProduct})
	if p := ProofOf(packaged, "en"); p.Verdict != VerdictCheck || !strings.Contains(p.Summary, "Check it") {
		t.Errorf("packaged: %+v", p)
	}
	if p := ProofOf(packaged, "pl"); !strings.Contains(p.Summary, "Do sprawdzenia") {
		t.Errorf("Polish: %+v", p)
	}

	foreign := match.Groups([]match.Finding{{Kind: match.KindExposedFile, TechID: "foreign-host", Host: "old.example.com", Port: 443, URL: "https://old.example.com/", Evidence: "x", Score: 55}})[0]
	if p := ProofOf(foreign, "en"); !strings.HasPrefix(p.Command, "openssl s_client -connect 'old.example.com:443' -servername 'old.example.com'") {
		t.Errorf("foreign host: %+v", p)
	}
	mail := match.Groups([]match.Finding{{Kind: match.KindEmail, TechID: "dmarc-missing", Host: "example.com", Score: 50}})[0]
	if p := ProofOf(mail, "en"); p.Command != "dig +short TXT 'example.com'; dig +short TXT '_dmarc.example.com'" {
		t.Errorf("mail: %+v", p)
	}
	// Nothing from a scanned system reaches a command unquoted.
	evil := match.Groups([]match.Finding{{Kind: match.KindTakeover, Host: "x';rm -rf ~;'.example.com", Score: 80}})[0]
	if p := ProofOf(evil, "en"); p.Command != "" {
		t.Errorf("unsafe name in a command: %q", p.Command)
	}
	odd := kevGroup(match.Finding{CVE: "CVE-1", Confidence: match.ConfidenceProduct})
	odd.URL = "https://vpn.example.com/a'b c"
	if p := ProofOf(odd, "en"); p.Command != "curl -sk -D - -o /dev/null 'https://vpn.example.com/a%27b%20c'" {
		t.Errorf("quoted path: %q", p.Command)
	}
	secret := match.Groups([]match.Finding{{Kind: match.KindSecret, Technology: "Stripe secret key", File: "app/.env", Line: 3, Fingerprint: "ab", Score: 90}})[0]
	if p := ProofOf(secret, "en"); p.Verdict != VerdictLikely || !strings.Contains(p.SeeIt, "app/.env:3") {
		t.Errorf("secret: %+v", p)
	}
}

func TestFixListShowsProof(t *testing.T) {
	g := kevGroup(match.Finding{CVE: "CVE-2024-21762", Version: "7.2.4", Confidence: match.ConfidenceVersion, DateAdded: "2024-02-09", Score: 90, Severity: match.Critical})
	var b strings.Builder
	if err := FixList(&b, g.Findings, Meta{Organization: "Acme", Lang: "en", Services: 1}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"**How sure:** Confirmed", "  - ✓ NVD lists version 7.2.4", "**See it yourself:**", "`curl -sk -D - -o /dev/null 'https://vpn.example.com/remote/login'`"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("fix list lacks %q:\n%s", want, b.String())
		}
	}
}
