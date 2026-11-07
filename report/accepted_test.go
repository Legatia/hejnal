package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

func wordpress(cve string, score int) match.Finding {
	return match.Finding{Key: "kev|www.example.com|443|" + cve, Kind: match.KindKEV, Host: "www.example.com", Port: 443,
		URL: "https://www.example.com/", TechID: "wordpress", Technology: "WordPress", CVE: cve, Name: "WordPress Core Vulnerability",
		DateAdded: "2026-09-25", Score: score, Severity: match.SeverityFor(score), Confidence: match.ConfidenceProduct}
}

// accept accepts the given findings of an item until the given day.
func accept(fs []match.Finding, until, reason, by string) match.Acceptance {
	g := match.Groups(fs)[0]
	a := match.Acceptance{Item: g.ID(), Key: g.Key, Reason: reason, By: by, AcceptedAt: now, Until: until}
	for _, f := range fs {
		a.Findings = append(a.Findings, f.Key)
	}
	return a
}

// acceptedFindings are: a WordPress item accepted until 2027-02-02 that has
// a new flaw since, an expired certificate accepted until then too, and a
// Jenkins admin page whose acceptance ended on 2026-11-01.
func acceptedFindings() ([]match.Finding, match.Group) {
	old, fresh := wordpress("CVE-2026-87902", 75), wordpress("CVE-2026-119977", 85)
	fresh.DateAdded = "2026-11-03"
	fs := findings()
	tls, admin := fs[2], fs[3]
	all := []match.Finding{fresh, old, tls, admin}
	marked := match.MarkAccepted(all, []match.Acceptance{
		accept([]match.Finding{old}, "2027-02-02", "Version 6.8.3 has the fix", "Anna Nowak"),
		accept([]match.Finding{tls}, "2027-02-02", "The host is retired next week", ""),
		accept([]match.Finding{admin}, "2026-11-01", "Only reachable over the VPN", "Jan"),
	}, now)
	return marked, match.Groups([]match.Finding{old})[0]
}

func TestFixListAccepted(t *testing.T) {
	fs, wp := acceptedFindings()
	var b strings.Builder
	if err := FixList(&b, fs, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	tlsID := match.ItemID("tls-expired|mail.example.com|443")
	for _, want := range []string{
		// The certificate is accepted, so it is not counted or listed as open.
		"**Fix now: 1 · This week: 0 · This month: 1 · Later: 0**",
		// The WordPress item is back with its new flaw only, and says so.
		"### 1. WordPress on www.example.com:443 · `" + wp.ID() + "`\n\n- **Accepted earlier:** Part of this item was accepted until 2027-02-02; see Accepted at the end.",
		"Known exploited flaws in this product: 1.",
		"**CVE-2026-119977**",
		"To close it, run `hejnal accept -item " + wp.ID() + " -reason \"...\"`.",
		// The admin page's acceptance has expired.
		"### 2. Jenkins admin interface reachable on ci.example.com:443 · `" + match.ItemID("admin-exposed|ci.example.com|443|jenkins") + "`\n\n- **Acceptance expired:** This item was accepted until 2026-11-01.",
		"## Accepted\n\nPeople checked these items and accepted them with `hejnal accept`.",
		"- `" + wp.ID() + "` WordPress on www.example.com:443: CVE-2026-87902 · reason: Version 6.8.3 has the fix · accepted by Anna Nowak · until 2027-02-02\n",
		"- `" + tlsID + "` Expired TLS certificate on mail.example.com:443 · reason: The host is retired next week · until 2027-02-02\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "### 3.") || strings.Contains(out, "**CVE-2026-87902**") {
		t.Errorf("accepted findings are listed as open:\n%s", out)
	}
	if strings.Index(out, "## Accepted") > strings.Index(out, "---\n") {
		t.Errorf("the Accepted section is not at the end:\n%s", out)
	}

	b.Reset()
	if err := FixList(&b, fs, meta("pl")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Zaakceptowane", "**Wcześniej zaakceptowane:**", "**Akceptacja wygasła:**",
		"powód: Version 6.8.3 has the fix · kto zaakceptował: Anna Nowak · ważne do 2027-02-02", "Aby go zamknąć, uruchom `hejnal accept -item"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("Polish fix list is missing %q\n%s", want, b.String())
		}
	}
}

func TestFixListEverythingAccepted(t *testing.T) {
	fs := findings()[2:3]
	fs = match.MarkAccepted(fs, []match.Acceptance{accept(fs, "2027-02-02", "Retired next week", "")}, now)
	var b strings.Builder
	if err := FixList(&b, fs, meta("en")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"**Fix now: 0 · This week: 0 · This month: 0 · Later: 0**", "Nothing open to fix. Accepted items are listed at the end.", "## Accepted"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("fix list is missing %q\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "Nothing to fix. Hejnal found no products") {
		t.Errorf("the fix list says nothing was found:\n%s", b.String())
	}
}

func TestFixListShowsItemIDs(t *testing.T) {
	ruledOut := wordpress("CVE-2025-11111", 20)
	ruledOut.Key, ruledOut.Host, ruledOut.Version, ruledOut.Confidence = "kev|old.example.com|443|CVE-2025-11111", "old.example.com", "6.8.3", match.ConfidenceRuledOut
	var b strings.Builder
	if err := FixList(&b, append(findings(), ruledOut), meta("en")); err != nil {
		t.Fatal(err)
	}
	for _, g := range match.Groups(append(findings(), ruledOut)) {
		if !strings.Contains(b.String(), "`"+g.ID()+"`") {
			t.Errorf("the fix list does not show the ID of %s:\n%s", g.Key, b.String())
		}
	}
	if !strings.Contains(b.String(), "- WordPress on old.example.com:443 (version `6.8.3`): CVE-2025-11111 · `") {
		t.Errorf("ruled-out item without its ID:\n%s", b.String())
	}
}

// TestAcceptedTextIsEscaped checks that a reason or name cannot add Markdown,
// HTML or lines to the fix list.
func TestAcceptedTextIsEscaped(t *testing.T) {
	fs := findings()[2:3]
	a := accept(fs, "2027-02-02", "ok\n## Fake heading <img src=x onerror=alert(1)> [click](https://evil.example) `code` *bold* | cell", "<b>Mallory</b>")
	fs = match.MarkAccepted(fs, []match.Acceptance{a}, now)
	var b strings.Builder
	if err := FixList(&b, fs, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, bad := range []string{"\n## Fake", "<img", "[click](", "`code`", "*bold*", "<b>"} {
		if strings.Contains(out, bad) {
			t.Errorf("fix list contains %q unescaped:\n%s", bad, out)
		}
	}
	for _, want := range []string{"reason: ok ## Fake heading &lt;img src=x onerror=alert(1)&gt; \\[click\\](https://evil.example) \\`code\\` \\*bold\\* \\| cell",
		"accepted by &lt;b&gt;Mallory&lt;/b&gt;"} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q:\n%s", want, out)
		}
	}
}

func TestSummaryLeavesOutAccepted(t *testing.T) {
	fs, _ := acceptedFindings()
	first := Summary(fs, match.Open(fs), nil, true, meta("en"))
	for _, want := range []string{"First check · Open: 2 (critical 1 · high 0 · medium 1 · low 0) · Accepted: 2",
		"[critical] WordPress on www.example.com:443: CVE-2026-119977\n",
		"[medium] Jenkins admin interface reachable on ci.example.com:443 · acceptance expired"} {
		if !strings.Contains(first, want) {
			t.Errorf("summary is missing %q:\n%s", want, first)
		}
	}
	if strings.Contains(first, "mail.example.com") || strings.Contains(first, "CVE-2026-87902") {
		t.Errorf("summary lists accepted findings:\n%s", first)
	}
	later := Summary(fs, fs, nil, false, meta("pl"))
	if !strings.Contains(later, "Nowe: 2 · Rozwiązane: 0 · Otwarte: 2 (krytyczne 1 · wysokie 0 · średnie 1 · niskie 0) · Zaakceptowane: 2") ||
		!strings.Contains(later, "akceptacja wygasła") {
		t.Errorf("Polish summary:\n%s", later)
	}
}

func TestMonthlyCountsAccepted(t *testing.T) {
	old := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	stays := kevFinding("b.example.com", "CVE-2019-11043", match.Medium)
	accepted := match.MarkAccepted([]match.Finding{old, stays}, []match.Acceptance{accept([]match.Finding{old}, "2027-02-02", "Patched", "")}, now)
	history := []*state.Snapshot{
		snap("2026-11-02", 5, old, stays),
		snap("2026-11-20", 5, accepted...),
	}
	var b strings.Builder
	if err := Monthly(&b, history, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Items fixed: 0",
		"Still open: 1 (critical 0 · high 0 · medium 1 · low 0)",
		"- Accepted, not fixed: 1\n",
		"## Accepted\n\n- [high] PHP on a.example.com:443: CVE-2024-4577 · until 2027-02-02\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("monthly report is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "## Fixed this month") {
		t.Errorf("an accepted item counts as fixed:\n%s", out)
	}
}

func TestItemTitle(t *testing.T) {
	gs := match.Groups(findings())
	if got := ItemTitle(gs[0], "en"); got != "Fortinet FortiGate SSL VPN on vpn.example.com:443" {
		t.Errorf("ItemTitle = %q", got)
	}
	if got := ItemTitle(gs[1], "pl"); got != "Wygasły certyfikat TLS na mail.example.com:443" {
		t.Errorf("Polish ItemTitle = %q", got)
	}
}
