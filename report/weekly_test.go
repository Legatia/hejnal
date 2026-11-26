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

func TestFixedItems(t *testing.T) {
	php := inventory.Technology{ID: "php", Name: "PHP"}
	upgraded := kevFinding("a.example.com", "CVE-2019-11043", match.High)
	upgraded.Confidence = match.ConfidenceVersion
	upgradedNow := upgraded
	upgradedNow.Confidence = match.ConfidenceRuledOut
	guessed := kevFinding("a.example.com", "CVE-2021-41773", match.Low) // product only
	guessed.TechID, guessed.Technology = "apache", "Apache"
	guessedNow := guessed
	guessedNow.Confidence = match.ConfidenceRuledOut
	cert := match.Finding{Key: "tls-expired|a.example.com|443", Kind: match.KindTLSExpired, Host: "a.example.com", Port: 443}
	mail := match.Finding{Key: "email|dmarc-missing|example.com", Kind: match.KindEmail, Host: "example.com", TechID: "dmarc-missing"}
	gone := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	gone.Port, gone.Key = 8443, "kev|a.example.com|8443|CVE-2024-4577"

	all := []match.Finding{upgradedNow, guessedNow}
	resolved := []match.Finding{upgraded, guessed, cert, mail, gone}
	inv := invWith(inventory.Service{Port: 443, TLS: &inventory.TLSInfo{}, Technologies: []inventory.Technology{php}})
	inv.Mail = []inventory.MailAuth{{Domain: "example.com"}}
	var got []string
	for _, g := range FixedItems(all, resolved, inv) {
		got = append(got, string(g.Kind)+"@"+g.Host)
	}
	slices.Sort(got)
	// The upgrade, the renewed certificate and the published mail record are
	// fixes. The flaw first seen without a version was never confirmed, and
	// the PHP on port 8443 is merely gone: that port no longer answers.
	want := []string{"email@example.com", "kev@a.example.com", "tls-expired@a.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("fixed items %v, want %v", got, want)
	}

	// A maintenance page: the site answers, but PHP no longer shows.
	php443 := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	if got := FixedItems(nil, []match.Finding{php443}, invWith(inventory.Service{Port: 443})); got != nil {
		t.Errorf("a product that stopped showing counts as fixed: %v", got)
	}
	// The same site still showing PHP, now without the flaw.
	if got := FixedItems(nil, []match.Finding{php443}, invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{php}})); len(got) != 1 {
		t.Errorf("PHP without the flaw not counted as fixed")
	}
	if got := FixedItems(nil, resolved, &inventory.Inventory{}); got != nil {
		t.Errorf("a run that reached nothing reports %d fixed items", len(got))
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
	title, lines := WeeklyLines(history, cat, phpInv, now, m)
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

	// A flaw listed this week in software found, but ruled out by its version.
	ruled := kevFinding("b.example.com", "CVE-2026-9001", match.High)
	ruled.Confidence = match.ConfidenceRuledOut
	h2 := append(history[:len(history):len(history)], snap("2026-11-23", 3, stays, ruled))
	_, lines = WeeklyLines(h2, cat, phpInv, now.Add(time.Hour), m)
	if !strings.Contains(strings.Join(lines, "\n"), "Flaws newly listed as exploited this week: 2. Software you run has 1 of them, but the versions it shows are not affected.") {
		t.Errorf("ruled-out flaw not reported as checked:\n%s", strings.Join(lines, "\n"))
	}

	// The same flaw affecting a system.
	hit := ruled
	hit.Confidence = match.ConfidenceVersion
	h3 := append(history[:len(history):len(history)], snap("2026-11-23", 3, stays, hit))
	_, lines = WeeklyLines(h3, cat, phpInv, now.Add(time.Hour), m)
	if !strings.Contains(strings.Join(lines, "\n"), "Your systems have 1 of them: they are on the fix list.") {
		t.Errorf("affecting flaw not reported:\n%s", strings.Join(lines, "\n"))
	}

	// Polish, without a catalog.
	m.Lang = "pl"
	title, lines = WeeklyLines(history, nil, phpInv, now, m)
	out = title + "\n" + strings.Join(lines, "\n")
	for _, want := range []string{"tydzień od 2026-11-16 do 2026-11-23", "Naprawione w tym tygodniu: 1", "żadna podatność nie została nowo oznaczona"} {
		if !strings.Contains(out, want) {
			t.Errorf("Polish weekly summary is missing %q\n%s", want, out)
		}
	}
}

func TestWeeklyLinesFirstWeekAndNoRuns(t *testing.T) {
	now := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	m := Meta{Organization: "Example", Lang: "en"}
	_, lines := WeeklyLines([]*state.Snapshot{snap("2026-11-20", 1)}, nil, nil, now, m)
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, "Hejnal started watching this week.") || !strings.Contains(out, "Nothing is open.") {
		t.Errorf("first-week summary:\n%s", out)
	}
	if strings.Contains(out, "Full list") {
		t.Errorf("points at the fix list with nothing open:\n%s", out)
	}
	_, lines = WeeklyLines([]*state.Snapshot{snap("2026-11-01", 1)}, nil, nil, now, m)
	if len(lines) != 1 || lines[0] != "No check ran in the last 7 days." {
		t.Errorf("summary without runs: %q", lines)
	}
	// A run that reached nothing does not make items look fixed.
	f := kevFinding("a.example.com", "CVE-2024-4577", match.High)
	f.Confidence = match.ConfidenceVersion
	down := snap("2026-11-22", 1)
	down.Services = 0
	_, lines = WeeklyLines([]*state.Snapshot{snap("2026-11-10", 1, f), snap("2026-11-20", 1, f), down}, nil, invWith(inventory.Service{Port: 443, Technologies: []inventory.Technology{{ID: "php"}}}), now, m)
	out = strings.Join(lines, "\n")
	if !strings.Contains(out, "Fixed this week: 0") || !strings.Contains(out, "Checks that reached no services: 1") {
		t.Errorf("outage summary:\n%s", out)
	}
}
