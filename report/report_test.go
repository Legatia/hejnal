package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func meta(lang string) Meta {
	return Meta{
		Organization: "Przykład <Sp. z o.o.>",
		GeneratedAt:  now,
		Lang:         lang,
		KEVVersion:   "2026.11.03",
		EPSSDate:     "2026-11-03",
		Assets:       3,
		Services:     5,
		Technologies: 7,
	}
}

func findings() []match.Finding {
	expired := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return []match.Finding{
		{
			Key: "kev|vpn.example.com|443|CVE-2025-61624", Kind: match.KindKEV, Host: "vpn.example.com", Port: 443,
			URL: "https://vpn.example.com/remote/login", TechID: "fortinet-fortigate", Technology: "Fortinet FortiGate SSL VPN",
			Evidence: "path /remote/login", CVE: "CVE-2025-61624", Name: "Fortinet Multiple Products Path Traversal Vulnerability",
			DateAdded: "2026-10-16", Forensics: true, EPSS: 0.42,
			Links: []string{"https://fortiguard.example/advisory", "https://www.cisa.gov/news-events/directives/bod-26-04"},
			Score: 95, Severity: match.Critical, Confidence: match.ConfidenceProduct,
		},
		{
			Key: "kev|vpn.example.com|443|CVE-2018-13379", Kind: match.KindKEV, Host: "vpn.example.com", Port: 443,
			URL: "https://vpn.example.com/remote/login", TechID: "fortinet-fortigate", Technology: "Fortinet FortiGate SSL VPN",
			CVE: "CVE-2018-13379", Name: "Fortinet FortiOS SSL VPN Path Traversal Vulnerability", DateAdded: "2021-11-03",
			Ransomware: true, Score: 60, Severity: match.Medium, Confidence: match.ConfidenceProduct,
		},
		{
			Key: "tls-expired|mail.example.com|443", Kind: match.KindTLSExpired, Host: "mail.example.com", Port: 443,
			Subject: "mail.example.com", Expires: &expired, Score: 70, Severity: match.High, Confidence: match.ConfidenceObserved,
		},
		{
			Key: "admin-exposed|ci.example.com|443|jenkins", Kind: match.KindAdminExposed, Host: "ci.example.com", Port: 443,
			URL: "https://ci.example.com/", TechID: "jenkins", Technology: "Jenkins", Evidence: "header X-Jenkins: 2.462.3",
			Score: 55, Severity: match.Medium, Confidence: match.ConfidenceObserved,
		},
	}
}

func TestFixListEnglish(t *testing.T) {
	var b strings.Builder
	if err := FixList(&b, findings(), meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Hejnal fix list: Przykład &lt;Sp. z o.o.&gt;",
		"CISA Known Exploited Vulnerabilities catalog 2026.11.03, FIRST EPSS scores of 2026-11-03.",
		"**Fix now: 1 · This week: 1 · This month: 1 · Later: 0**",
		"## Fix now (critical)",
		"### 1. Fortinet FortiGate SSL VPN on vpn.example.com:443",
		"Known exploited flaws in this product: 2. The newest was listed as exploited on 2026-10-16.",
		"**Check for compromise:**",
		"**CVE-2025-61624**: Fortinet Multiple Products Path Traversal Vulnerability · added 2026-10-16 · EPSS 42% · forensic triage",
		"used in ransomware campaigns",
		"version not shown",
		"<https://fortiguard.example/advisory>",
		"> Hejnal recognised the product but did not verify its version",
		"## This week (high)",
		"### 2. Expired TLS certificate on mail.example.com:443",
		"expired on 2026-10-01",
		"### 3. Jenkins admin interface reachable on ci.example.com:443",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "news-events/directives") {
		t.Error("fix list links to CISA's US federal directive")
	}
	if strings.Contains(out, "<Sp.") {
		t.Error("organisation name was not escaped")
	}
}

func TestFixListPolish(t *testing.T) {
	var b strings.Builder
	if err := FixList(&b, findings(), meta("pl")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# Lista poprawek Hejnal: Przykład",
		"## Napraw teraz (krytyczne)",
		"### 1. Fortinet FortiGate SSL VPN na vpn.example.com:443",
		"Wygasły certyfikat TLS na mail.example.com:443",
		"wersja nieujawniona",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Polish fix list is missing %q", want)
		}
	}
}

func TestFixListEmpty(t *testing.T) {
	var b strings.Builder
	FixList(&b, nil, meta("en"))
	if !strings.Contains(b.String(), "Nothing to fix") {
		t.Errorf("empty fix list:\n%s", b.String())
	}
	m := meta("en")
	m.Services = 0
	b.Reset()
	FixList(&b, nil, m)
	if !strings.Contains(b.String(), "reached no services") {
		t.Errorf("fix list with no services:\n%s", b.String())
	}
}

func TestFixListCollapsesLongLists(t *testing.T) {
	var fs []match.Finding
	for i := 0; i < 8; i++ {
		fs = append(fs, match.Finding{
			Key: fmt.Sprintf("kev|h|443|CVE-2020-%04d", i), Kind: match.KindKEV, Host: "h", Port: 443, TechID: "x",
			Technology: "X", CVE: fmt.Sprintf("CVE-2020-%04d", i), DateAdded: "2021-11-03", Score: 40, Severity: match.Low,
		})
	}
	var b strings.Builder
	FixList(&b, fs, meta("en"))
	if !strings.Contains(b.String(), "…and 3 more") {
		t.Errorf("long list not collapsed:\n%s", b.String())
	}
}

func TestNIS2(t *testing.T) {
	var b strings.Builder
	if err := NIS2(&b, findings(), meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# NIS2 early warning: draft",
		"within 24 hours",
		"within 72 hours",
		"within one month",
		"S46",
		"| vpn.example.com:443 | Fortinet FortiGate SSL VPN | CVE-2025-61624 | 2026-10-16 (CISA) | yes |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("NIS2 draft is missing %q", want)
		}
	}
	if strings.Contains(out, "CVE-2018-13379") {
		t.Error("NIS2 draft lists a medium finding without forensic triage")
	}

	b.Reset()
	NIS2(&b, nil, meta("pl"))
	for _, want := range []string{"NIS2: wczesne ostrzeżenie", "24 godzin", "nie wykazało krytycznych"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("Polish NIS2 draft is missing %q", want)
		}
	}
}

// enisaFindings are flaws from ENISA's list: one only ENISA lists, and one
// ENISA listed 18 days before CISA.
func enisaFindings() []match.Finding {
	return []match.Finding{
		{
			Key: "kev|gw.example.com|8291|CVE-2026-67276", Kind: match.KindKEV, Host: "gw.example.com", Port: 8291,
			URL: "tcp://gw.example.com:8291", TechID: "mikrotik-routeros-services", Technology: "MikroTik RouterOS",
			CVE: "CVE-2026-67276", EUVD: "EUVD-2026-72024", ListedBy: []string{match.ListENISA},
			Name: "MikroTik RouterOS vulnerability (MikroTrick)", DateAdded: "2026-09-05",
			Links: []string{"https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve"},
			Score: 90, Severity: match.Critical, Confidence: match.ConfidenceProduct,
		},
		{
			Key: "kev|win.example.com|443|CVE-2026-96951", Kind: match.KindKEV, Host: "win.example.com", Port: 443,
			URL: "https://win.example.com/", TechID: "iis", Technology: "Microsoft IIS",
			CVE: "CVE-2026-96951", EUVD: "EUVD-2026-100274", ListedBy: []string{match.ListCISA, match.ListENISA},
			Name: "Microsoft Windows Vulnerability", DateAdded: "2026-10-13", ENISAEarlier: "2026-09-25", Forensics: true,
			Score: 80, Severity: match.High, Confidence: match.ConfidenceProduct,
		},
	}
}

func TestENISAListings(t *testing.T) {
	m := meta("en")
	m.EUVDDate = "2026-11-07"
	var b strings.Builder
	if err := FixList(&b, enisaFindings(), m); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Sources: CISA Known Exploited Vulnerabilities catalog 2026.11.03, ENISA EUVD list of exploited vulnerabilities of 2026-11-07, FIRST EPSS scores of 2026-11-03.",
		"**CVE-2026-67276** (EUVD-2026-72024): MikroTik RouterOS vulnerability (MikroTrick) · listed by ENISA, not CISA, on 2026-09-05",
		"**CVE-2026-96951** (EUVD-2026-100274): Microsoft Windows Vulnerability · added 2026-10-13 · ENISA listed it on 2026-09-25, 18 days before CISA",
		"<https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve>",
		"ENISA European Vulnerability Database (EUVD)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q:\n%s", want, out)
		}
	}

	b.Reset()
	m.Lang = "pl"
	FixList(&b, enisaFindings(), m)
	for _, want := range []string{"lista wykorzystywanych podatności ENISA EUVD z 2026-11-07", "na liście ENISA (nie CISA) od 2026-09-05",
		"ENISA wpisała ją 2026-09-25, 18 dni przed CISA"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("Polish fix list is missing %q", want)
		}
	}

	b.Reset()
	NIS2(&b, enisaFindings(), meta("en"))
	for _, want := range []string{
		"| gw.example.com:8291 | MikroTik RouterOS | CVE-2026-67276 / EUVD-2026-72024 | 2026-09-05 (ENISA) | no |",
		"| win.example.com:443 | Microsoft IIS | CVE-2026-96951 / EUVD-2026-100274 | 2026-09-25 (ENISA) | yes |",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("NIS2 draft is missing %q:\n%s", want, b.String())
		}
	}

	if got := daysBetween("2026-09-23", "2026-09-24"); got != 1 {
		t.Errorf("daysBetween = %d, want 1", got)
	}
	b.Reset()
	fs := enisaFindings()[1:]
	fs[0].ENISAEarlier = "2026-10-12"
	FixList(&b, fs, meta("en"))
	if !strings.Contains(b.String(), "ENISA listed it on 2026-10-12, a day before CISA") {
		t.Errorf("one day earlier not said:\n%s", b.String())
	}
}

func TestSummary(t *testing.T) {
	fs := findings()
	first := Summary(fs, fs, nil, true, meta("en"))
	for _, want := range []string{"*Hejnal* · Przykład &lt;Sp. z o.o.&gt;", "First check · Open: 3", "[critical] Fortinet FortiGate SSL VPN on vpn.example.com:443: CVE-2025-61624, CVE-2018-13379"} {
		if !strings.Contains(first, want) {
			t.Errorf("first-run summary is missing %q:\n%s", want, first)
		}
	}
	later := Summary(fs, fs[2:3], fs[:1], false, meta("pl"))
	for _, want := range []string{"Nowe: 1 · Rozwiązane: 1 · Otwarte: 3", "[wysokie] Wygasły certyfikat TLS na mail.example.com:443"} {
		if !strings.Contains(later, want) {
			t.Errorf("summary is missing %q:\n%s", want, later)
		}
	}
}

func TestTranslationsComplete(t *testing.T) {
	for _, lang := range Languages {
		for key := range messages["en"] {
			if _, ok := messages[lang][key]; !ok {
				t.Errorf("%s is missing %q", lang, key)
			}
		}
		for key := range messages[lang] {
			if _, ok := messages["en"][key]; !ok {
				t.Errorf("%s has %q, which English does not", lang, key)
			}
		}
	}
	if !ValidLang("pl") || ValidLang("de") {
		t.Error("ValidLang is wrong")
	}
}

func TestPercent(t *testing.T) {
	for p, want := range map[float64]string{0.001: "<1%", 0.42: "42%", 0.999: ">99%"} {
		if got := percent(p); got != want {
			t.Errorf("percent(%v) = %q, want %q", p, got, want)
		}
	}
}

func TestFixListVersionVerdicts(t *testing.T) {
	fs := []match.Finding{
		{Key: "kev|w|443|CVE-2026-109618", Kind: match.KindKEV, Host: "w", Port: 443, TechID: "php", Technology: "PHP",
			Version: "8.3.12", CVE: "CVE-2026-109618", Name: "PHP Memory Corruption Vulnerability", DateAdded: "2026-10-26",
			Score: 95, Severity: match.Critical, Confidence: match.ConfidenceVersion},
		{Key: "kev|w|443|CVE-2024-4577", Kind: match.KindKEV, Host: "w", Port: 443, TechID: "php", Technology: "PHP",
			Version: "8.3.12", CVE: "CVE-2024-4577", DateAdded: "2024-06-12", Score: 20, Severity: match.Low,
			Confidence: match.ConfidenceRuledOut},
		{Key: "kev|j|443|CVE-2024-23897", Kind: match.KindKEV, Host: "j", Port: 443, TechID: "jenkins", Technology: "Jenkins",
			Version: "2.462.3", CVE: "CVE-2024-23897", DateAdded: "2024-08-19", Score: 20, Severity: match.Low,
			Confidence: match.ConfidenceRuledOut},
		{Key: "kev|x|443|CVE-2025-0001", Kind: match.KindKEV, Host: "x", Port: 443, TechID: "php", Technology: "PHP",
			Version: "8.3.7", CVE: "CVE-2025-0001", DateAdded: "2025-01-01", Score: 60, Severity: match.Medium,
			Confidence: match.ConfidenceProduct, Condition: "microsoft windows"},
	}
	var b strings.Builder
	if err := FixList(&b, fs, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"**Fix now: 1 · This week: 0 · This month: 1 · Later: 0**",
		"Known exploited flaws in this product: 1.",
		"version affected",
		"**Ruled out by version:** CVE-2024-4577",
		"Hejnal compared version `8.3.12` with the affected versions NVD lists",
		"only on microsoft windows",
		"## Probably fixed already",
		"- Jenkins on j:443 (version `2.462.3`): CVE-2024-23897",
		"not endorsed or certified by the NVD",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q\n%s", want, out)
		}
	}
	if s := Summary(fs, fs, nil, true, meta("en")); strings.Contains(s, "CVE-2024-23897") || strings.Contains(s, "CVE-2024-4577") {
		t.Errorf("summary mentions ruled-out flaws:\n%s", s)
	}
}

func TestFixListSecretsAndBreaches(t *testing.T) {
	fs := []match.Finding{
		{Key: "secret|0123456789abcdef|app/settings.py", Kind: match.KindSecret, TechID: "github-pat",
			Technology: "GitHub personal access token", Evidence: "ghp_ab… (40 chars)", File: "app/settings.py", Line: 12,
			Fingerprint: "0123456789abcdef", Score: 90, Severity: match.Critical, Confidence: match.ConfidenceObserved},
		{Key: "secret|0123456789abcdef|old/config.py", Kind: match.KindSecret, TechID: "github-pat",
			Technology: "GitHub personal access token", Evidence: "ghp_ab… (40 chars)", File: "old/config.py", Line: 3,
			Commit: "8f2c1d0e9b7a6f5e4d3c2b1a", Fingerprint: "0123456789abcdef", Score: 90, Severity: match.Critical,
			Confidence: match.ConfidenceObserved},
		{Key: "breach|example.com|Adobe", Kind: match.KindBreach, Host: "example.com", TechID: "Adobe", Name: "Adobe",
			BreachDate: "2013-10-04", DateAdded: "2013-12-04", Accounts: 5, Passwords: true, Score: 60, Severity: match.Medium,
			Confidence: match.ConfidenceObserved},
		{Key: "breach|example.com|Spamlist", Kind: match.KindBreach, Host: "example.com", TechID: "Spamlist", Name: "Spam <list>",
			BreachDate: "2020-01-01", DateAdded: "2020-02-01", Accounts: 40, Score: 30, Severity: match.Low,
			Confidence: match.ConfidenceObserved},
	}
	var b strings.Builder
	if err := FixList(&b, fs, meta("en")); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"**Fix now: 1 · This week: 0 · This month: 1 · Later: 0**",
		"### 1. Secret in source code: GitHub personal access token",
		"- **Secret:** `ghp_ab… (40 chars)`",
		"  - `app/settings.py:12`\n",
		"  - `old/config.py:3` · commit `8f2c1d0e9b7a`\n",
		"### 2. Accounts on example.com in known data breaches",
		"appear in 2 data breaches, 1 of which exposed passwords",
		"  - **Adobe** · breached 2013-10-04 · 5 accounts · passwords exposed\n",
		"  - **Spam &lt;list&gt;** · breached 2020-01-01 · 40 accounts\n",
		"- **Source:** [Have I Been Pwned](https://haveibeenpwned.com/) (CC BY 4.0)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "example.com:0") || strings.Contains(out, " :0") {
		t.Errorf("fix list shows a port for secrets or breaches:\n%s", out)
	}
	s := Summary(fs, fs, nil, true, meta("pl"))
	for _, want := range []string{
		"[krytyczne] Sekret w kodzie źródłowym: GitHub personal access token: app/settings.py:12",
		"[średnie] Konta w domenie example.com w znanych wyciekach danych",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary is missing %q\n%s", want, s)
		}
	}
}
