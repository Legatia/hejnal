package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

func snap(at string, assets int, fs ...match.Finding) *state.Snapshot {
	t, _ := time.Parse("2006-01-02", at)
	return &state.Snapshot{Organization: "Example", GeneratedAt: t.Add(7 * time.Hour), Assets: assets, Services: assets * 2, Technologies: assets * 3, Findings: fs}
}

func kevFinding(host, cve string, sev match.Severity) match.Finding {
	return match.Finding{Key: "kev|" + host + "|443|" + cve, Kind: match.KindKEV, Host: host, Port: 443, TechID: "php",
		Technology: "PHP", CVE: cve, Severity: sev, Score: 80, Confidence: match.ConfidenceProduct}
}

func TestMonthly(t *testing.T) {
	old := kevFinding("a.example.com", "CVE-2024-4577", match.High)      // open since October, fixed in November
	stays := kevFinding("b.example.com", "CVE-2019-11043", match.Medium) // open all along
	fresh := kevFinding("c.example.com", "CVE-2026-109618", match.Critical)
	ruled := kevFinding("d.example.com", "CVE-2021-41773", match.Low)
	ruled.Confidence = match.ConfidenceRuledOut
	history := []*state.Snapshot{
		snap("2026-10-20", 4, old, stays),
		snap("2026-11-02", 5, old, stays, ruled),
		snap("2026-11-10", 6, stays, fresh),
		snap("2026-11-28", 6, stays, fresh),
		snap("2026-12-01", 7, stays),
	}
	var b strings.Builder
	month := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	if err := Monthly(&b, history, month, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Hejnal monthly report, November 2026: ",
		"Period: 2026-11-01 to 2026-11-30 · Runs: 3",
		"| Hosts | 4 | 6 |",
		"New items to fix: 1",
		"Items fixed: 1",
		"Median time to fix: 21.0 days",
		"Still open: 2 (critical 1 · high 0 · medium 1 · low 0)",
		"## Fixed this month\n\n- [high] PHP on a.example.com:443",
		"PHP on b.example.com:443: CVE-2019-11043 · open since 2026-10-20",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("monthly report is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "CVE-2021-41773") {
		t.Error("ruled-out flaw appears in the monthly report")
	}

	b.Reset()
	Monthly(&b, history, month, meta("pl"))
	if !strings.Contains(b.String(), "Raport miesięczny Hejnal, listopad 2026") {
		t.Errorf("Polish title missing:\n%s", b.String())
	}
	b.Reset()
	Monthly(&b, history, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), meta("en"))
	if !strings.Contains(b.String(), "did not run in this month") {
		t.Errorf("empty month:\n%s", b.String())
	}
}

func TestMonthlyIgnoresRunsThatReachedNothing(t *testing.T) {
	stays := kevFinding("b.example.com", "CVE-2019-11043", match.Medium)
	outage := snap("2026-11-29", 0) // reached no services: everything looks fixed
	history := []*state.Snapshot{snap("2026-11-02", 5, stays), snap("2026-11-20", 5, stays), outage}
	var b strings.Builder
	if err := Monthly(&b, history, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Items fixed: 0", "Still open: 1", "1 runs reached none of your services", "Runs: 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("monthly report is missing %q\n%s", want, out)
		}
	}
}
