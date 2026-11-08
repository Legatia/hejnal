package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

func overviewInventory() *inventory.Inventory {
	return &inventory.Inventory{Organization: "Przykład <Sp. z o.o.>", Assets: []inventory.Asset{
		{Host: "vpn.example.com", Services: []inventory.Service{{Port: 443, Technologies: []inventory.Technology{
			{ID: "fortinet-fortigate", Name: "Fortinet FortiGate SSL VPN", Category: "edge"}}}}},
		{Host: "gw.example.com", Services: []inventory.Service{{Port: 8291, Technologies: []inventory.Technology{
			{ID: "mikrotik-routeros-services", Name: "MikroTik RouterOS", Category: "network"}}}}},
		{Host: "www.example.com", Services: []inventory.Service{{Port: 443, Technologies: []inventory.Technology{
			{ID: "nginx", Name: "nginx", Category: "server"}, {ID: "wordpress", Name: "WordPress", Category: "cms"}}}}},
		{Host: "ci.example.com", Services: []inventory.Service{{Port: 443, Technologies: []inventory.Technology{
			{ID: "jenkins", Name: "Jenkins", Category: "devops"}, {ID: "nginx", Name: "nginx", Category: "server"}}}}},
	}}
}

// writeSample saves the page for a person to look at when HEJNAL_SAMPLES
// names a directory.
func writeSample(t *testing.T, name, page string) {
	if dir := os.Getenv("HEJNAL_SAMPLES"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOverview(t *testing.T) {
	fs := append(findings(), enisaFindings()...)
	m := meta("en")
	m.EUVDDate, m.KEVFlaws = "2026-11-07", 1783
	// The VPN was already open in a run a week earlier.
	earlier := &state.Snapshot{GeneratedAt: m.GeneratedAt.Add(-7 * 24 * time.Hour), Services: 4, Findings: fs[:1]}
	var b strings.Builder
	if err := Overview(&b, fs, m, OverviewOptions{By: "Legatia Solutions", Inventory: overviewInventory(), History: []*state.Snapshot{earlier}}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	writeSample(t, "overview-en.html", out)
	for _, want := range []string{
		`<html lang="en">`,
		"<h1>Przykład &lt;Sp. z o.o.&gt;</h1>",
		"Prepared by Legatia Solutions",
		`<section class="verdict urgent">`,
		"Needs action now: 4",
		"<b>1,783</b><span>Exploited flaws checked</span>",
		"Fortinet FortiGate SSL VPN on vpn.example.com:443",
		"Attackers have been exploiting flaws in this product since 2021-11-03",
		"Hejnal first saw this on 2026-10-28.",
		"<td>CVE-2026-67276<span class=\"euvd\">EUVD-2026-72024</span></td><td>ENISA</td><td class=\"num\">2026-09-05</td>",
		"<td>CVE-2026-96951<span class=\"euvd\">EUVD-2026-100274</span></td><td>CISA, ENISA</td><td class=\"num\">2026-09-25</td>",
		`<a href="https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve">`,
		"<td>VPNs and gateways</td><td class=\"num\">1</td><td>Fortinet FortiGate SSL VPN</td>",
		"<td>Web servers</td><td class=\"num\">2</td><td>nginx</td>",
		"ENISA EUVD list of exploited vulnerabilities of 2026-11-07",
		"Every check is non-intrusive",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("overview is missing %q", want)
		}
	}
	// VPNs come before web servers, as attackers look for them first.
	if strings.Index(out, "VPNs and gateways") > strings.Index(out, "Web servers") {
		t.Error("exposed products are not ordered by interest to attackers")
	}
	if strings.Contains(out, "`") || strings.Contains(out, "news-events/directives") {
		t.Error("overview has Markdown or CISA's US directive link")
	}
	if n := strings.Count(out, `<article class="item">`); n != 5 {
		t.Errorf("%d items, want 5", n)
	}

	// Beyond five items, the rest are counted.
	var many []match.Finding
	for i := 0; i < 7; i++ {
		many = append(many, match.Finding{Key: fmt.Sprintf("admin|h%d|443|jenkins", i), Kind: match.KindAdminExposed,
			Host: fmt.Sprintf("h%d.example.com", i), Port: 443, TechID: "jenkins", Technology: "Jenkins", Score: 50, Severity: match.Medium})
	}
	b.Reset()
	Overview(&b, many, meta("en"), OverviewOptions{})
	if out := b.String(); strings.Count(out, `<article class="item">`) != overviewItems || !strings.Contains(out, "Another 2 items are in the full fix list.") ||
		!strings.Contains(out, "Worth fixing: 7") {
		t.Errorf("long overview:\n%s", out)
	}
}

func TestOverviewPolish(t *testing.T) {
	m := meta("pl")
	var b strings.Builder
	if err := Overview(&b, enisaFindings(), m, OverviewOptions{Inventory: overviewInventory()}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	writeSample(t, "overview-pl.html", out)
	for _, want := range []string{`<html lang="pl">`, "Przegląd ekspozycji w internecie", "Do pilnego działania: 2",
		"Do poprawy w pierwszej kolejności", "VPN i bramy", "Jak to sprawdzono", "Atakujący wykorzystują podatności w tym produkcie od 2026-09-05"} {
		if !strings.Contains(out, want) {
			t.Errorf("Polish overview is missing %q", want)
		}
	}
	if strings.Contains(out, "Prepared by") {
		t.Error("English left in the Polish overview")
	}
}

func TestNumber(t *testing.T) {
	for _, c := range []struct {
		lang string
		n    int
		want string
	}{{"en", 0, "0"}, {"en", 999, "999"}, {"en", 1783, "1,783"}, {"en", 1234567, "1,234,567"},
		{"pl", 1783, "1783"}, {"pl", 12345, "12\u00a0345"}, {"en", -1234, "-1,234"}} {
		if got := number(c.lang, c.n); got != c.want {
			t.Errorf("number(%s, %d) = %q, want %q", c.lang, c.n, got, c.want)
		}
	}
}

func TestOverviewClearAndEmpty(t *testing.T) {
	m := meta("en")
	m.KEVFlaws = 1783
	var b strings.Builder
	if err := Overview(&b, nil, m, OverviewOptions{Inventory: overviewInventory()}); err != nil {
		t.Fatal(err)
	}
	writeSample(t, "overview-clear.html", b.String())
	if out := b.String(); !strings.Contains(out, `<section class="verdict clear">`) || !strings.Contains(out, "No exploited flaws found") ||
		strings.Contains(out, "Fix first") {
		t.Errorf("clean overview:\n%s", out)
	}
	// Accepted findings do not count against the verdict.
	fs := enisaFindings()
	for i := range fs {
		fs[i].Accepted = &match.Acceptance{Item: "x", Reason: "isolated lab", Until: "2027-01-01"}
	}
	b.Reset()
	Overview(&b, fs, m, OverviewOptions{})
	if out := b.String(); !strings.Contains(out, "No exploited flaws found") || !strings.Contains(out, "checked and accepted, left out here: 2") {
		t.Errorf("accepted findings:\n%s", out)
	}
	m.Services = 0
	b.Reset()
	Overview(&b, nil, m, OverviewOptions{})
	if !strings.Contains(b.String(), "Nothing reachable was found") {
		t.Error("an overview with no services should say so")
	}
}
