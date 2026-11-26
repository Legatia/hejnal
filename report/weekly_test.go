package report

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

func invWith(services ...inventory.Service) *inventory.Inventory {
	return &inventory.Inventory{Assets: []inventory.Asset{{Host: "a.example.com", Services: services}}}
}

func run(fs ...match.Finding) *state.Snapshot {
	return &state.Snapshot{EOLDate: "2026-11-20", Services: 1, Findings: fs}
}

func fixedKinds(gs []match.Group) []string {
	var out []string
	for _, g := range gs {
		out = append(out, string(g.Kind)+"@"+g.Host)
	}
	slices.Sort(out)
	return out
}

func TestFixedItems(t *testing.T) {
	php := inventory.Technology{ID: "php", Name: "PHP", Version: "8.3.14"}
	upgraded := kevFinding("a.example.com", "CVE-2019-11043", match.High)
	upgraded.Confidence = match.ConfidenceVersion
	upgradedNow := upgraded
	upgradedNow.Confidence = match.ConfidenceRuledOut
	guessed := kevFinding("a.example.com", "CVE-2021-41773", match.Low) // product only
	guessed.TechID, guessed.Technology = "apache", "Apache"
	guessedNow := guessed
	guessedNow.Confidence = match.ConfidenceRuledOut
	cert := match.Finding{Key: "tls-expired|a.example.com|443", Kind: match.KindTLSExpired, Host: "a.example.com", Port: 443}
	dmarc := match.Finding{Key: "email|example.com|dmarc-missing", Kind: match.KindEmail, Host: "example.com", TechID: "dmarc-missing"}
	gone := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	gone.Port, gone.Key = 8443, "kev|a.example.com|8443|CVE-2024-4577"

	resolved := []match.Finding{upgraded, guessed, cert, dmarc, gone}
	inv := invWith(inventory.Service{Port: 443, TLS: &inventory.TLSInfo{}, Technologies: []inventory.Technology{php}})
	inv.Mail = []inventory.MailAuth{{Domain: "example.com", SPFKnown: true, DMARCKnown: true}}
	got := fixedKinds(FixedItems(run(upgradedNow, guessedNow), resolved, inv))
	// The upgrade, the renewed certificate and the published mail record are
	// fixes. The flaw first seen without a version was never confirmed, and
	// the PHP on port 8443 is merely gone: that port no longer answers.
	want := []string{"email@example.com", "kev@a.example.com", "tls-expired@a.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("fixed items %v, want %v", got, want)
	}

	// A maintenance page: the site answers, but PHP no longer shows.
	php443 := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	if got := FixedItems(run(), []match.Finding{php443}, invWith(inventory.Service{Port: 443})); got != nil {
		t.Errorf("a product that stopped showing counts as fixed: %v", got)
	}
	// The same site still showing PHP, now without the flaw.
	if got := FixedItems(run(), []match.Finding{php443}, invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{php}})); len(got) != 1 {
		t.Errorf("PHP without the flaw not counted as fixed")
	}
	if got := FixedItems(run(), resolved, &inventory.Inventory{}); got != nil {
		t.Errorf("a run that reached nothing reports %d fixed items", len(got))
	}
}

func TestFixedItemsNeedsEvidence(t *testing.T) {
	certInv := invWith(inventory.Service{Port: 443, TLS: &inventory.TLSInfo{}})

	// An expiring certificate that has now expired got worse.
	expiring := match.Finding{Key: "tls-expiring|a.example.com|443", Kind: match.KindTLSExpiring, Host: "a.example.com", Port: 443}
	expired := match.Finding{Key: "tls-expired|a.example.com|443", Kind: match.KindTLSExpired, Host: "a.example.com", Port: 443}
	if got := FixedItems(run(expired), []match.Finding{expiring}, certInv); got != nil {
		t.Errorf("an expired certificate counts as the expiring one fixed: %v", fixedKinds(got))
	}

	// Mail records: a lookup that failed, or a record that got worse.
	spfWeak := match.Finding{Key: "email|example.com|spf-weak", Kind: match.KindEmail, Host: "example.com", TechID: "spf-weak"}
	spfMissing := match.Finding{Key: "email|example.com|spf-missing", Kind: match.KindEmail, Host: "example.com", TechID: "spf-missing"}
	dmarcMissing := match.Finding{Key: "email|example.com|dmarc-missing", Kind: match.KindEmail, Host: "example.com", TechID: "dmarc-missing"}
	timedOut := invWith(inventory.Service{Port: 443})
	timedOut.Mail = []inventory.MailAuth{{Domain: "example.com"}}
	if got := FixedItems(run(), []match.Finding{spfWeak, dmarcMissing}, timedOut); got != nil {
		t.Errorf("mail items fixed by a lookup that failed: %v", fixedKinds(got))
	}
	read := invWith(inventory.Service{Port: 443})
	read.Mail = []inventory.MailAuth{{Domain: "example.com", SPFKnown: true, DMARCKnown: true}}
	if got := FixedItems(run(spfMissing), []match.Finding{spfWeak}, read); got != nil {
		t.Errorf("a deleted SPF record counts as the weak one fixed: %v", fixedKinds(got))
	}
	// A DMARC fix still counts while the SPF record has its own problem.
	if got := fixedKinds(FixedItems(run(spfWeak), []match.Finding{dmarcMissing}, read)); !slices.Equal(got, []string{"email@example.com"}) {
		t.Errorf("DMARC fix next to an SPF problem: %v", got)
	}

	// End of support: a hidden version, a packaged one, or no dates.
	eol := match.Finding{Key: "eol|a.example.com|443|nginx|1.18", Kind: match.KindEOL, Host: "a.example.com", Port: 443, TechID: "nginx",
		Technology: "nginx", Release: "1.18", Confidence: match.ConfidenceObserved}
	for name, c := range map[string]struct {
		tech inventory.Technology
		snap *state.Snapshot
	}{
		"hidden version": {inventory.Technology{ID: "nginx"}, run()},
		"packaged":       {inventory.Technology{ID: "nginx", Version: "1.18.0", Packaged: true}, run()},
		"no dates":       {inventory.Technology{ID: "nginx", Version: "1.26.2"}, &state.Snapshot{Services: 1}},
	} {
		if got := FixedItems(c.snap, []match.Finding{eol}, invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{c.tech}})); got != nil {
			t.Errorf("%s: end-of-support item counts as fixed", name)
		}
	}
	upgraded := invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{{ID: "nginx", Version: "1.26.2"}}})
	if got := FixedItems(run(), []match.Finding{eol}, upgraded); len(got) != 1 {
		t.Error("an upgrade to a supported release does not count as fixed")
	}
}

func TestFixedLines(t *testing.T) {
	fixed := match.Groups([]match.Finding{kevFinding("a.example.com", "CVE-2024-4577", match.High)})
	if got := FixedLines(fixed, "en"); len(got) != 1 || got[0] != "✓ Fixed, no longer found: PHP on a.example.com:443" {
		t.Errorf("English: %q", got)
	}
	if got := FixedLines(fixed, "pl"); len(got) != 1 || got[0] != "✓ Naprawione, już nie znalezione: PHP na a.example.com:443" {
		t.Errorf("Polish: %q", got)
	}
}

func weekCatalog(entries ...kev.Vulnerability) *kev.Catalog {
	return &kev.Catalog{Vulnerabilities: entries}
}

func TestWeeklyLines(t *testing.T) {
	now := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	old := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	old.Confidence = match.ConfidenceVersion
	stays := kevFinding("b.example.com", "CVE-2019-11043", match.Medium)
	expiring := match.Finding{Key: "tls-expiring|c.example.com|443", Kind: match.KindTLSExpiring, Host: "c.example.com", Port: 443, Severity: match.Medium}
	exp := now.Add(10 * 24 * time.Hour)
	expiring.Expires = &exp
	history := []*state.Snapshot{
		snap("2026-10-01", 3, stays),
		snap("2026-11-15", 3, old, stays),
		snap("2026-11-18", 3, old, stays),
		snap("2026-11-20", 3, stays, expiring),
		snap("2026-11-22", 3, stays, expiring),
	}
	m := Meta{Organization: "Example", Lang: "en"}
	// The last run still reached PHP on a and b, and a certificate on c.
	phpInv := &inventory.Inventory{Assets: []inventory.Asset{
		{Host: "a.example.com", Services: []inventory.Service{{Port: 443, Technologies: []inventory.Technology{{ID: "php"}}}}},
		{Host: "b.example.com", Services: []inventory.Service{{Port: 443, Technologies: []inventory.Technology{{ID: "php"}}}}},
		{Host: "c.example.com", Services: []inventory.Service{{Port: 443, TLS: &inventory.TLSInfo{}}}},
	}}

	// Two flaws listed this week, neither in software found.
	cat := weekCatalog(
		kev.Vulnerability{CVEID: "CVE-2026-9001", DateAdded: "2026-11-19"},
		kev.Vulnerability{CVEID: "CVE-2026-9002", DateAdded: "2026-11-20", ENISAOnly: true},
		kev.Vulnerability{CVEID: "CVE-2026-9003", DateAdded: "2026-11-22", ENISAEarlier: "2026-11-10"}, // ENISA listed it before this week
		kev.Vulnerability{CVEID: "CVE-2026-9004", DateAdded: "2026-11-02"},
	)
	title, lines := WeeklyLines(history, cat, phpInv, time.Time{}, now, m)
	out := title + "\n" + strings.Join(lines, "\n")
	for _, want := range []string{
		"Hejnal · Example · week of 2026-11-16 to 2026-11-23",
		"Checked on 3 of the last 7 days · Hosts: 3 · Services: 6 · Products recognised: 9",
		"Flaws newly listed as exploited this week: 2. Hejnal checked each one against the software it found on your systems: none is affected.",
		"Fixed this week: 1 · New this week: 1",
		"Open: 2 (critical 0 · high 0 · medium 2 · low 0)",
		"Oldest open item: PHP on b.example.com:443, open since 2026-10-01 (days open: 53)",
		"Coming up: 2026-12-03 · ",
		"Full list: hejnal report fixlist",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("weekly summary is missing %q\n%s", want, out)
		}
	}

	// From the last summary on: since Thursday the 19th.
	title, lines = WeeklyLines(history, cat, phpInv, time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC), now, m)
	out = title + "\n" + strings.Join(lines, "\n")
	for _, want := range []string{"week of 2026-11-19 to 2026-11-23", "Checked on 2 of the last 4 days", "listed as exploited this week: 2."} {
		if !strings.Contains(out, want) {
			t.Errorf("summary since the last one is missing %q\n%s", want, out)
		}
	}

	// A flaw listed this week in software found, but ruled out by its version.
	ruled := kevFinding("b.example.com", "CVE-2026-9001", match.High)
	ruled.Confidence = match.ConfidenceRuledOut
	h2 := append(history[:len(history):len(history)], snap("2026-11-23", 3, stays, ruled))
	_, lines = WeeklyLines(h2, cat, phpInv, time.Time{}, now.Add(time.Hour), m)
	if !strings.Contains(strings.Join(lines, "\n"), "Flaws newly listed as exploited this week: 2. Software you run has 1 of them, but the versions it shows are not affected.") {
		t.Errorf("ruled-out flaw not reported as checked:\n%s", strings.Join(lines, "\n"))
	}

	// The same flaw affecting a system.
	hit := ruled
	hit.Confidence = match.ConfidenceVersion
	h3 := append(history[:len(history):len(history)], snap("2026-11-23", 3, stays, hit))
	_, lines = WeeklyLines(h3, cat, phpInv, time.Time{}, now.Add(time.Hour), m)
	if !strings.Contains(strings.Join(lines, "\n"), "Your systems have 1 of them: they are on the fix list.") {
		t.Errorf("affecting flaw not reported:\n%s", strings.Join(lines, "\n"))
	}

	// Polish, without a catalog: nothing is said about newly listed flaws.
	m.Lang = "pl"
	title, lines = WeeklyLines(history, nil, phpInv, time.Time{}, now, m)
	out = title + "\n" + strings.Join(lines, "\n")
	for _, want := range []string{"tydzień od 2026-11-16 do 2026-11-23", "Naprawione w tym tygodniu: 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("Polish weekly summary is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "Podatności nowo") || strings.Contains(out, "żadna podatność") {
		t.Errorf("summary without a catalog talks about newly listed flaws:\n%s", out)
	}
}

func TestWeeklyLinesFirstWeekAndNoRuns(t *testing.T) {
	now := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	m := Meta{Organization: "Example", Lang: "en"}
	_, lines := WeeklyLines([]*state.Snapshot{snap("2026-11-20", 1)}, nil, nil, time.Time{}, now, m)
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, "Hejnal started watching this week.") || !strings.Contains(out, "Nothing is open.") {
		t.Errorf("first-week summary:\n%s", out)
	}
	if strings.Contains(out, "Full list") {
		t.Errorf("points at the fix list with nothing open:\n%s", out)
	}
	_, lines = WeeklyLines([]*state.Snapshot{snap("2026-11-01", 1)}, nil, nil, time.Time{}, now, m)
	if len(lines) != 1 || lines[0] != "No check ran in the last 7 days." {
		t.Errorf("summary without runs: %q", lines)
	}
	// A run that reached nothing does not make items look fixed.
	f := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	f.Confidence = match.ConfidenceVersion
	down := snap("2026-11-22", 1)
	down.Services = 0
	_, lines = WeeklyLines([]*state.Snapshot{snap("2026-11-10", 1, f), snap("2026-11-20", 1, f), down}, nil, invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{{ID: "php"}}}), time.Time{}, now, m)
	out = strings.Join(lines, "\n")
	if !strings.Contains(out, "Fixed this week: 0") || !strings.Contains(out, "Checks that reached no services: 1") {
		t.Errorf("outage summary:\n%s", out)
	}
}

func TestWeeklyLinesOutageWeek(t *testing.T) {
	now := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	m := Meta{Organization: "Example", Lang: "en"}
	critical := kevFinding("a.example.com", "CVE-2024-4577", match.Critical)
	history := []*state.Snapshot{snap("2026-11-14", 1, critical)}
	for d := 17; d <= 23; d++ {
		down := snap(time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC).Format(time.DateOnly), 1)
		down.Services = 0
		history = append(history, down)
	}
	cat := weekCatalog(kev.Vulnerability{CVEID: "CVE-2026-9001", DateAdded: "2026-11-19"})
	_, lines := WeeklyLines(history, cat, &inventory.Inventory{}, time.Time{}, now, m)
	out := strings.Join(lines, "\n")
	for _, want := range []string{
		"Checks that reached no services: 7",
		"No check in this period reached your systems. What follows is from the last check that did, on 2026-11-14.",
		"Hejnal could not check them yet",
		"Open: 1 (critical 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("outage-week summary is missing %q\n%s", want, out)
		}
	}
	for _, wrong := range []string{"Nothing is open", "none is affected", "Fixed this week"} {
		if strings.Contains(out, wrong) {
			t.Errorf("outage-week summary claims %q\n%s", wrong, out)
		}
	}
	// Runs that never reached anything.
	_, lines = WeeklyLines(history[1:], cat, nil, time.Time{}, now, m)
	if out := strings.Join(lines, "\n"); !strings.Contains(out, "No check has reached any of your systems yet.") || strings.Contains(out, "Nothing is open") {
		t.Errorf("summary without any reached run:\n%s", out)
	}
}

func TestWeeklyLinesCountsEachFlawOnce(t *testing.T) {
	m := Meta{Organization: "Example", Lang: "en"}
	stays := kevFinding("b.example.com", "CVE-2019-11043", match.Medium)
	inv := invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{{ID: "php"}}})
	var history []*state.Snapshot
	for d := 9; d <= 23; d++ {
		history = append(history, snap(time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC).Format(time.DateOnly), 1, stays))
	}
	// Listed on Monday the 16th, after that morning's summary.
	cat := weekCatalog(kev.Vulnerability{CVEID: "CVE-2026-9100", DateAdded: "2026-11-16"})
	mon16 := time.Date(2026, 11, 16, 7, 0, 40, 0, time.UTC)
	mon23 := time.Date(2026, 11, 23, 7, 0, 45, 0, time.UTC)
	_, first := WeeklyLines(history[:8], cat, inv, time.Date(2026, 11, 9, 7, 0, 40, 0, time.UTC), mon16, m)
	_, second := WeeklyLines(history, cat, inv, mon16, mon23, m)
	if out := strings.Join(first, "\n"); !strings.Contains(out, "No flaw was newly listed") {
		t.Errorf("the summary sent that morning counts it:\n%s", out)
	}
	out := strings.Join(second, "\n")
	if !strings.Contains(out, "listed as exploited this week: 1.") {
		t.Errorf("the next summary leaves it out:\n%s", out)
	}
	// Daily runs, a few seconds apart from week to week.
	if !strings.Contains(out, "Checked on 7 of the last 7 days") {
		t.Errorf("day count:\n%s", out)
	}
}

func TestWeeklyLinesFlawsAfterTheLastReachedRun(t *testing.T) {
	m := Meta{Organization: "Example", Lang: "en"}
	stays := kevFinding("b.example.com", "CVE-2019-11043", match.Medium)
	var history []*state.Snapshot
	for d := 9; d <= 16; d++ {
		s := snap(time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC).Format(time.DateOnly), 1, stays)
		if d >= 15 {
			s.Services, s.Findings = 0, nil // Sunday and Monday reach nothing
		}
		history = append(history, s)
	}
	cat := weekCatalog(
		kev.Vulnerability{CVEID: "CVE-2026-9200", DateAdded: "2026-11-12"},
		kev.Vulnerability{CVEID: "CVE-2026-9201", DateAdded: "2026-11-15"},
	)
	from := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	_, lines := WeeklyLines(history, cat, nil, from, now, m)
	out := strings.Join(lines, "\n")
	for _, want := range []string{
		"Flaws newly listed as exploited this week: 1. Hejnal checked each one",
		"Flaws listed as exploited after the last check that reached your systems: 1. Hejnal could not check them yet.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "No flaw was newly listed") {
		t.Errorf("summary says no flaw was listed:\n%s", out)
	}
}
