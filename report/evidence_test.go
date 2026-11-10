package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// evidenceHistory is two months of runs every two days, from 1 September
// 2026: a FortiGate open from the start and fixed on 21 September, a
// MikroTik flaw found the day after ENISA listed it and fixed three days
// later, a WordPress flaw open since 25 September, a Jenkins panel accepted
// on 1 October, and one run on 11 October that reached nothing.
func evidenceHistory() []*state.Snapshot {
	day := func(d string) time.Time { t, _ := time.Parse("2006-01-02", d); return t.Add(6 * time.Hour) }
	forti := match.Finding{Key: "kev|vpn.example.com|443|CVE-2018-13379", Kind: match.KindKEV, Host: "vpn.example.com", Port: 443,
		TechID: "fortinet-fortigate", Technology: "Fortinet FortiGate SSL VPN", CVE: "CVE-2018-13379", DateAdded: "2021-11-03",
		ListedBy: []string{match.ListCISA}, Score: 95, Severity: match.Critical}
	mikrotik := match.Finding{Key: "kev|gw.example.com|8291|CVE-2026-67276", Kind: match.KindKEV, Host: "gw.example.com", Port: 8291,
		TechID: "mikrotik-routeros-services", Technology: "MikroTik RouterOS", CVE: "CVE-2026-67276", EUVD: "EUVD-2026-72024",
		DateAdded: "2026-09-05", ListedBy: []string{match.ListENISA}, Score: 90, Severity: match.Critical}
	wp := match.Finding{Key: "kev|www.example.com|443|CVE-2026-87902", Kind: match.KindKEV, Host: "www.example.com", Port: 443,
		TechID: "wordpress", Technology: "WordPress", CVE: "CVE-2026-87902", DateAdded: "2026-09-25", ENISAEarlier: "2026-09-23",
		ListedBy: []string{match.ListCISA, match.ListENISA}, Score: 80, Severity: match.High}
	jenkins := match.Finding{Key: "admin-exposed|ci.example.com|443|jenkins", Kind: match.KindAdminExposed, Host: "ci.example.com",
		Port: 443, TechID: "jenkins", Technology: "Jenkins", Score: 50, Severity: match.Medium}
	accepted := jenkins
	accepted.Accepted = &match.Acceptance{Item: "a1b2c3d4", Reason: "only reachable from the office network", By: "IT lead", Until: "2027-04-01"}

	var out []*state.Snapshot
	for t := day("2026-09-01"); t.Before(day("2026-11-01")); t = t.AddDate(0, 0, 2) {
		d := t.Format("2006-01-02")
		s := &state.Snapshot{Organization: "Przykład Sp. z o.o.", GeneratedAt: t, KEVVersion: "2026.10.30", EUVDDate: "2026-10-30",
			KEVFlaws: 1783, Assets: 4, Services: 6, Technologies: 8}
		if d == "2026-10-11" {
			s.Services = 0
			out = append(out, s)
			continue
		}
		if d < "2026-09-21" {
			s.Findings = append(s.Findings, forti)
		}
		if d >= "2026-09-06" && d < "2026-09-09" {
			s.Findings = append(s.Findings, mikrotik)
		}
		if d >= "2026-09-25" {
			s.Findings = append(s.Findings, wp)
		}
		if d >= "2026-10-01" {
			s.Findings = append(s.Findings, accepted)
		} else {
			s.Findings = append(s.Findings, jenkins)
		}
		out = append(out, s)
	}
	return out
}

func TestExposures(t *testing.T) {
	runs, unreachable, exps := Exposures(evidenceHistory())
	if len(runs) != 30 || unreachable != 1 {
		t.Fatalf("%d runs, %d unreachable; want 30 and 1", len(runs), unreachable)
	}
	byTech := map[string]Exposure{}
	for _, e := range exps {
		byTech[e.Group.TechID] = e
	}
	day := func(e Exposure) string { return e.Fixed.Format("2006-01-02") }
	if f := byTech["fortinet-fortigate"]; !f.AtStart || f.Open() || day(f) != "2026-09-21" || f.Listed != "2021-11-03" {
		t.Errorf("FortiGate: %+v", f)
	}
	// Seen on the 7th (the run after ENISA listed it), gone by the 9th.
	if m := byTech["mikrotik-routeros-services"]; m.AtStart || m.FirstSeen.Format("2006-01-02") != "2026-09-07" || day(m) != "2026-09-09" ||
		m.Days(time.Time{}) != 2 {
		t.Errorf("MikroTik: %+v", m)
	}
	if w := byTech["wordpress"]; !w.Open() || w.Listed != "2026-09-23" {
		t.Errorf("WordPress: %+v", w)
	}
	if j := byTech["jenkins"]; !j.Open() || !j.Accepted {
		t.Errorf("Jenkins: %+v", j)
	}
	// A run that reached nothing does not count as fixing everything.
	for _, e := range exps {
		if e.Fixed.Format("2006-01-02") == "2026-10-11" {
			t.Errorf("%s was fixed by the run that reached nothing", e.Group.Key)
		}
	}
}

func TestEvidence(t *testing.T) {
	m := meta("en")
	m.Organization = "Przykład Sp. z o.o."
	m.GeneratedAt = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	var b strings.Builder
	if err := Evidence(&b, evidenceHistory(), m, EvidenceOptions{By: "Legatia Solutions"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	writeSample(t, "evidence-en.html", out)
	for _, want := range []string{
		"Period covered: 2026-09-01 to 2026-10-31",
		"since 2026-09-01: 30 runs, the latest on 2026-10-31",
		"Runs that reached no services, left out: 1.",
		"<b>30</b><span>Runs</span>",
		"<b>2.1</b><span>Days between runs, on average</span>",
		"<b>3</b><span>Exploited-flaw items found</span>",
		"<b>2</b><span>Of them fixed</span>",
		"<b>11.0</b><span>Median days to fix</span>",
		"Checks ran 30 times between 2026-09-01 and 2026-10-31, on average every 2.1 days; the longest gap between runs was 4.0 days.",
		"European Vulnerability Database (EUVD). The latest run checked 1,783 flaws.",
		"the median time from detection to fix was 11.0 days: 1 of 2 were fixed within 7 days and 2 within 30 days.",
		"Open now: 1, the oldest for 36.0 days.",
		"Items accepted now: 1",
		`<td class="item-title">WordPress on www.example.com:443</td><td class="num">2026-09-23</td><td class="num">2026-09-25</td><td class="num"></td><td class="num">36.0</td><td><span class="st critical">Open</span></td>`,
		`<td class="item-title">Fortinet FortiGate SSL VPN on vpn.example.com:443</td><td class="num">2021-11-03</td><td class="num">2026-09-01</td><td class="num">2026-09-21</td><td class="num">≥ 20.0</td>`,
		"<td>September 2026</td><td class=\"num\">15</td><td class=\"num\">6</td>",
		"only reachable from the office network (checked by IT lead, until 2027-04-01)",
		"Fingerprint of the runs used",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("evidence is missing %q", want)
		}
	}
	// The open item comes before fixed ones.
	if strings.Index(out, "WordPress on") > strings.Index(out, "Fortinet FortiGate SSL VPN on") {
		t.Error("open items should come first")
	}

	// The same runs give the same fingerprint; a changed run does not.
	h := evidenceHistory()
	fp := runsFingerprint(h)
	if runsFingerprint(evidenceHistory()) != fp {
		t.Error("fingerprint is not stable")
	}
	h[3].Findings = nil
	if runsFingerprint(h) == fp {
		t.Error("fingerprint did not change with the data")
	}
}

func TestEvidencePolishAndPeriods(t *testing.T) {
	m := meta("pl")
	var b strings.Builder
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := Evidence(&b, evidenceHistory(), m, EvidenceOptions{Since: since}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	writeSample(t, "evidence-pl.html", out)
	for _, want := range []string{
		`<html lang="pl">`, "Dowód monitorowania podatności", "Okres: od 2026-10-01 do 2026-10-31",
		"średnio co 2,1 dnia", "Ostatni przebieg sprawdził podatności: 1783.",
		"Wykryto podatności wykorzystywane przez atakujących, ale żadna nie została jeszcze naprawiona.",
		"październik 2026",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Polish evidence is missing %q", want)
		}
	}
	// Before the period, nothing: the September fixes are left out.
	if strings.Contains(out, "FortiGate") {
		t.Error("an item from before the period is listed")
	}

	b.Reset()
	Evidence(&b, nil, meta("en"), EvidenceOptions{})
	if !strings.Contains(b.String(), "No saved runs in this period yet.") {
		t.Errorf("empty evidence:\n%s", b.String())
	}
}

func TestEvidenceControlsAndJSON(t *testing.T) {
	m := meta("en")
	m.Organization = "Acme"
	var b strings.Builder
	if err := Evidence(&b, evidenceHistory(), m, EvidenceOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Controls this evidence supports", "CC7.1", "A.8.8", "Art. 21(2)(e)"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("page lacks %q", want)
		}
	}
	b.Reset()
	if err := EvidenceJSON(&b, evidenceHistory(), m, EvidenceOptions{By: "Legatia"}); err != nil {
		t.Fatal(err)
	}
	var rec EvidenceRecord
	if err := json.Unmarshal([]byte(b.String()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Schema != EvidenceSchema || rec.Runs.Count != 30 || rec.Runs.AverageDaysApart != 2.1 || rec.PreparedBy != "Legatia" ||
		len(rec.Exploited) != 3 || len(rec.Controls) != 5 || rec.Fingerprint == "" {
		t.Fatalf("record = %+v", rec)
	}
	fixed := 0
	for _, it := range rec.Exploited {
		if len(it.CVEs) == 0 || it.ID == "" {
			t.Errorf("item = %+v", it)
		}
		if it.Status == "fixed" && it.Fixed != nil {
			fixed++
		}
	}
	if fixed != 2 {
		t.Errorf("%d fixed, want 2", fixed)
	}
}

// ruledOutHistory is the README's quick start: a run that sees Next.js
// without a version, then a run with -checks that sees a version outside
// the affected range. conf is how sure the first run was.
func ruledOutHistory(conf string) []*state.Snapshot {
	next := kevFinding("www.example.com", "CVE-2025-55182", match.High)
	next.TechID, next.Technology, next.DateAdded, next.Confidence = "nextjs", "Next.js", "2025-12-05", conf
	ruled := next
	ruled.Version, ruled.Confidence, ruled.Score, ruled.Severity = "16.4.5", match.ConfidenceRuledOut, 20, match.Low
	return []*state.Snapshot{snap("2026-11-10", 1, next), snap("2026-11-12", 1, ruled)}
}

// A flaw reported without a version and then ruled out by the version was
// never confirmed, so the evidence must not count it as found and fixed.
func TestEvidenceRuledOutIsNotAFix(t *testing.T) {
	_, _, exps := Exposures(ruledOutHistory(match.ConfidenceProduct))
	if len(exps) != 1 || !exps[0].RuledOut || exps[0].Open() {
		t.Fatalf("exposures: %+v", exps)
	}
	var b strings.Builder
	if err := Evidence(&b, ruledOutHistory(match.ConfidenceProduct), meta("en"), EvidenceOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"<b>0</b><span>Exploited-flaw items found</span>",
		"<b>0</b><span>Of them fixed</span>",
		"No flaws known to be exploited were found in this period.",
		`<span class="st fixed">Ruled out by version</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("evidence is missing %q", want)
		}
	}
	for _, not := range []string{"<span>Median days to fix</span>", "the median time from detection to fix", `<span class="st fixed">Fixed</span>`} {
		if strings.Contains(out, not) {
			t.Errorf("evidence counts a ruled-out item as fixed: found %q", not)
		}
	}

	b.Reset()
	if err := EvidenceJSON(&b, ruledOutHistory(match.ConfidenceProduct), meta("en"), EvidenceOptions{}); err != nil {
		t.Fatal(err)
	}
	var rec EvidenceRecord
	if err := json.Unmarshal([]byte(b.String()), &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Exploited) != 1 {
		t.Fatalf("exploited: %+v", rec.Exploited)
	}
	if it := rec.Exploited[0]; it.Status != "ruled-out" || it.Fixed != nil || it.RuledOut == nil || it.DaysExposed != 0 {
		t.Errorf("JSON item: %+v", it)
	}
}

// An item seen with an affected version and later with a fixed one was
// upgraded: that is a real fix.
func TestEvidenceUpgradeIsAFix(t *testing.T) {
	_, _, exps := Exposures(ruledOutHistory(match.ConfidenceVersion))
	if len(exps) != 1 || exps[0].RuledOut || exps[0].Open() || exps[0].Days(time.Time{}) != 2 {
		t.Fatalf("exposures: %+v", exps)
	}
	var b strings.Builder
	if err := Evidence(&b, ruledOutHistory(match.ConfidenceVersion), meta("en"), EvidenceOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<b>1</b><span>Exploited-flaw items found</span>", "<b>1</b><span>Of them fixed</span>", `<span class="st fixed">Fixed</span>`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("evidence is missing %q", want)
		}
	}
}

// An item ruled out and then seen without a version again is open again.
func TestExposureReopensAfterRuledOut(t *testing.T) {
	h := ruledOutHistory(match.ConfidenceProduct)
	again := h[0].Findings[0]
	h = append(h, snap("2026-11-14", 1, again))
	_, _, exps := Exposures(h)
	if len(exps) != 1 || exps[0].RuledOut || !exps[0].Open() {
		t.Fatalf("exposures: %+v", exps)
	}
}
