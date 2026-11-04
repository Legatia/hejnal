package match

import (
	"math"
	"testing"
	"time"

	"github.com/Legatia/hejnal/internal/epss"
	"github.com/Legatia/hejnal/internal/fingerprint"
	"github.com/Legatia/hejnal/internal/inventory"
	"github.com/Legatia/hejnal/internal/kev"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func tech(id, name, category, version string, admin bool) inventory.Technology {
	return inventory.Technology{ID: id, Name: name, Category: category, Version: version, Admin: admin, Evidence: "test"}
}

func sampleInventory() *inventory.Inventory {
	wp := []inventory.Technology{
		tech("php", "PHP", "language", "8.3.12", false),
		tech("wordpress", "WordPress", "cms", "6.8.1", false),
	}
	return &inventory.Inventory{Organization: "Example", Assets: []inventory.Asset{
		{Host: "vpn.example.com", Services: []inventory.Service{{
			Port: 443, Scheme: "https", URL: "https://vpn.example.com/", FinalURL: "https://vpn.example.com/remote/login?lang=en",
			TLS:          &inventory.TLSInfo{Subject: "vpn.example.com", NotAfter: now.Add(-48 * time.Hour)},
			Technologies: []inventory.Technology{tech("fortinet-fortigate", "Fortinet FortiGate SSL VPN", "edge", "", false)},
		}}},
		{Host: "www.example.com", Services: []inventory.Service{
			// Port 80 redirects to HTTPS: its findings belong to port 443.
			{Port: 80, Scheme: "http", URL: "http://www.example.com/", FinalURL: "https://www.example.com/", Technologies: wp},
			{Port: 443, Scheme: "https", URL: "https://www.example.com/", Technologies: wp,
				TLS: &inventory.TLSInfo{Subject: "www.example.com", NotAfter: now.Add(10 * 24 * time.Hour)}},
		}},
		{Host: "ci.example.com", Services: []inventory.Service{{
			Port: 443, Scheme: "https", URL: "https://ci.example.com/",
			TLS:          &inventory.TLSInfo{Subject: "ci.example.com", NotAfter: now.Add(200 * 24 * time.Hour)},
			Technologies: []inventory.Technology{tech("jenkins", "Jenkins", "devops", "2.462.3", true)},
		}}},
		{Host: "app.example.com", Services: []inventory.Service{{
			Port: 8080, Scheme: "http", URL: "http://app.example.com:8080/",
			Technologies: []inventory.Technology{tech("tomcat", "Apache Tomcat", "server", "", false)},
		}}},
	}}
}

func run(t *testing.T, scores map[string]epss.Score) []Finding {
	t.Helper()
	cat, err := kev.Load("../../testdata/kev_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := fingerprint.Default()
	if err != nil {
		t.Fatal(err)
	}
	return Run(sampleInventory(), cat, eng, Options{Now: now, EPSS: scores})
}

func byKey(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Key] = f
	}
	return m
}

func TestRun(t *testing.T) {
	fs := run(t, map[string]epss.Score{"CVE-2025-61624": {CVE: "CVE-2025-61624", EPSS: 0.5, Percentile: 0.97}})
	got := byKey(fs)

	want := map[string]struct {
		score    int
		severity Severity
	}{
		// 19 days old (+20), edge (+10), forensic triage (+5), EPSS 0.5 (+5): capped at 100.
		"kev|vpn.example.com|443|CVE-2025-61624": {100, Critical},
		// About 100 days old (+0), edge (+10).
		"kev|vpn.example.com|443|CVE-2025-68686": {70, High},
		// Years old (-20), edge (+10), ransomware (+10).
		"kev|vpn.example.com|443|CVE-2018-13379": {60, Medium},
		// One day old (+20), forensic triage (+5).
		"kev|www.example.com|443|CVE-2026-119977": {85, Critical},
		// 40 days old (+10), forensic triage (+5).
		"kev|www.example.com|443|CVE-2026-87902":   {75, High},
		"kev|www.example.com|443|CVE-2026-109618":  {85, Critical},
		"kev|www.example.com|443|CVE-2026-109619":  {85, Critical},
		"kev|www.example.com|443|CVE-2024-4577":    {50, Medium},
		"kev|www.example.com|443|CVE-2019-11043":   {50, Medium},
		"kev|ci.example.com|443|CVE-2024-23897":    {50, Medium},
		"kev|app.example.com|8080|CVE-2025-24813":  {40, Low},
		"tls-expired|vpn.example.com|443":          {70, High},
		"tls-expiring|www.example.com|443":         {50, Medium},
		"admin-exposed|ci.example.com|443|jenkins": {55, Medium},
	}
	for key, w := range want {
		f, ok := got[key]
		if !ok {
			t.Errorf("missing finding %s", key)
			continue
		}
		if f.Score != w.score || f.Severity != w.severity {
			t.Errorf("%s: score %d %s, want %d %s", key, f.Score, f.Severity, w.score, w.severity)
		}
	}
	if len(fs) != len(want) {
		for _, f := range fs {
			if _, ok := want[f.Key]; !ok {
				t.Errorf("unexpected finding %s", f.Key)
			}
		}
	}

	// Entries that must not match: a WordPress plugin, PHPMailer, FortiMail
	// and a Fortinet "Multiple Products" entry that does not name FortiOS.
	for _, cve := range []string{"CVE-2020-25213", "CVE-2016-10033", "CVE-2026-104286", "CVE-2025-32756", "CVE-2021-41773"} {
		for _, f := range fs {
			if f.CVE == cve {
				t.Errorf("%s matched %s", cve, f.Key)
			}
		}
	}

	f := got["kev|vpn.example.com|443|CVE-2025-61624"]
	if f.Confidence != ConfidenceProduct || !f.Forensics || f.EPSS != 0.5 || f.URL != "https://vpn.example.com/remote/login?lang=en" {
		t.Errorf("finding details = %+v", f)
	}
	if fs[0].Score != 100 {
		t.Errorf("findings not sorted: first is %s", fs[0].Key)
	}
}

func TestNoCatalogStillChecksHygiene(t *testing.T) {
	eng, _ := fingerprint.Default()
	fs := Run(sampleInventory(), nil, eng, Options{Now: now})
	if len(fs) != 3 {
		t.Errorf("got %d findings, want 3 hygiene findings", len(fs))
	}
}

func TestGroups(t *testing.T) {
	gs := Groups(run(t, nil))
	if len(gs) != 8 {
		for _, g := range gs {
			t.Logf("%s %s:%d %s %d", g.Kind, g.Host, g.Port, g.TechID, len(g.Findings))
		}
		t.Fatalf("got %d groups, want 8", len(gs))
	}
	first := gs[0]
	if first.Severity != Critical || first.Kind != KindKEV {
		t.Errorf("first group = %+v", first)
	}
	var php Group
	for _, g := range gs {
		if g.TechID == "php" {
			php = g
		}
	}
	if len(php.Findings) != 4 || php.Newest() != "2026-10-26" || !php.Forensics() {
		t.Errorf("php group = %d findings, newest %s, forensics %v", len(php.Findings), php.Newest(), php.Forensics())
	}
	c := CountGroups(gs)
	if c[Critical] != 3 || c[High] != 1 || c[Medium] != 3 || c[Low] != 1 {
		t.Errorf("counts = %v", c)
	}
}

func TestSeverity(t *testing.T) {
	for score, want := range map[int]Severity{100: Critical, 85: Critical, 84: High, 70: High, 69: Medium, 50: Medium, 49: Low, 0: Low} {
		if got := SeverityFor(score); got != want {
			t.Errorf("SeverityFor(%d) = %s, want %s", score, got, want)
		}
	}
	if s, err := ParseSeverity("HIGH"); err != nil || s != High {
		t.Errorf("ParseSeverity(HIGH) = %q, %v", s, err)
	}
	if s, err := ParseSeverity("none"); err != nil || s != "" {
		t.Errorf("ParseSeverity(none) = %q, %v", s, err)
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("ParseSeverity accepted an unknown value")
	}
	fs := []Finding{{Severity: Medium}}
	if !AtLeast(fs, Medium) || AtLeast(fs, High) || AtLeast(fs, "") {
		t.Error("AtLeast is wrong")
	}
}

func TestScoreIgnoresInvalidEPSS(t *testing.T) {
	v := kev.Vulnerability{DateAdded: "2026-11-01", ForensicTriage: "Yes"}
	base := Score(v, "cms", 0, now)
	for _, p := range []float64{math.NaN(), -3, math.Inf(-1)} {
		if got := Score(v, "cms", p, now); got != base {
			t.Errorf("Score with EPSS %v = %d, want %d", p, got, base)
		}
	}
	if got := Score(v, "cms", 7, now); got != base+10 {
		t.Errorf("Score with EPSS 7 = %d, want it treated as 1 (%d)", got, base+10)
	}
}

func TestOrigin(t *testing.T) {
	cases := []struct {
		svc  inventory.Service
		host string
		port int
	}{
		{inventory.Service{Port: 80, URL: "http://a.example/", FinalURL: "https://a.example/login"}, "a.example", 443},
		{inventory.Service{Port: 8080, URL: "http://a.example:8080/"}, "a.example", 8080},
		{inventory.Service{Port: 443, URL: "https://[2001:db8::1]/"}, "2001:db8::1", 443},
		{inventory.Service{Port: 22, Scheme: "tcp"}, "h.example", 22},
	}
	for _, c := range cases {
		host, port, _ := origin("h.example", c.svc)
		if host != c.host || port != c.port {
			t.Errorf("origin(%+v) = %s:%d, want %s:%d", c.svc, host, port, c.host, c.port)
		}
	}
}

func TestCVEs(t *testing.T) {
	got := CVEs([]Finding{{CVE: "CVE-2"}, {CVE: "CVE-1"}, {CVE: "CVE-2"}, {}})
	if len(got) != 2 || got[0] != "CVE-1" {
		t.Errorf("CVEs = %v", got)
	}
}
