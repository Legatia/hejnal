package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
)

// eolFindings are nginx 1.24, past its end of support, PHP 8.2, whose
// support ends on 31 December 2026, and Confluence 7.4, past its end of
// support on no known day, with no newer release to suggest.
func eolFindings() []match.Finding {
	base := func(tech, name, release, version string) match.Finding {
		return match.Finding{
			Key: "eol|shop.example.com|443|" + tech + "|" + release, Kind: match.KindEOL, Host: "shop.example.com", Port: 443,
			URL: "https://shop.example.com/", TechID: tech, Technology: name, Version: version, Category: "server",
			Evidence: "header Server: " + tech + "/" + version, Release: release,
			Links: []string{"https://endoflife.date/" + tech}, Confidence: match.ConfidenceObserved,
		}
	}
	nginx := base("nginx", "nginx", "1.24", "1.24.0")
	nginx.SupportEnds, nginx.SupportEnded, nginx.UpgradeTo = "2024-04-23", true, []string{"1.30.6", "1.31.8"}
	nginx.Score, nginx.Severity = 55, match.Medium
	php := base("php", "PHP", "8.2", "8.2.10")
	php.SupportEnds, php.UpgradeTo = "2026-12-31", []string{"8.3.36", "8.5.12"}
	php.Score, php.Severity = 30, match.Low
	confluence := base("confluence", "Confluence", "7.4", "7.4.18")
	confluence.SupportEnded = true
	confluence.Score, confluence.Severity = 55, match.Medium
	return []match.Finding{nginx, php, confluence}
}

func fixList(t *testing.T, fs []match.Finding, m Meta) string {
	t.Helper()
	var b strings.Builder
	if err := FixList(&b, fs, m); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestFixListEndOfSupport(t *testing.T) {
	fs := eolFindings()
	php := match.Groups(fs[1:2])[0].ID()
	m := meta("en")
	m.EOLDate = "2026-11-14"
	out := fixList(t, fs, m)
	for _, want := range []string{
		"FIRST EPSS scores of 2026-11-03, endoflife.date support dates of 2026-11-14.",
		"nginx 1.24 past end of support on shop.example.com:443",
		"Support for nginx 1.24 ended on 2024-04-23. Flaws found in it since then are not fixed.",
		"Upgrade to a supported release: `1.30.6` is the closest, `1.31.8` the newest.",
		"**Seen at:** `https://shop.example.com/` (`header Server: nginx/1.24.0`) · version `1.24.0`",
		"**Source:** <https://endoflife.date/nginx>",
		"**How sure:** Confirmed",
		"✓ endoflife.date lists the end of support for nginx 1.24 as 2024-04-23.",
		"Ask the server for its version, and compare it with https://endoflife.date/nginx: `curl -sk -D - -o /dev/null 'https://shop.example.com/'`",
		"**Rough effort:** about two hours",
		"Confluence 7.4 past end of support on shop.example.com:443",
		"Support for Confluence 7.4 has ended. Flaws found in it are not fixed any more.",
		"Move to a release that still gets fixes.",
		"✓ endoflife.date lists Confluence 7.4 as past its end of support.",
		"## Later (low)",
		"PHP 8.2 support ending soon on shop.example.com:443",
		"Support for PHP 8.2 ends on 2026-12-31. After that, flaws found in it are not fixed.",
		"✓ endoflife.date lists the end of support for PHP 8.2 as 2026-12-31.",
		"## Coming up\n\nDates known in advance, for the next 90 days.\n\n- **2026-12-31** · PHP 8.2 support ending soon on shop.example.com:443 · `" + php + "`\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q:\n%s", want, out)
		}
	}
	// What has ended is not coming up.
	if soon := out[strings.Index(out, "## Coming up"):]; strings.Contains(soon, "nginx") || strings.Contains(soon, "Confluence") {
		t.Errorf("ended releases listed as coming up:\n%s", soon)
	}
}

func TestFixListEndOfSupportPolish(t *testing.T) {
	m := meta("pl")
	m.EOLDate = "2026-11-14"
	out := fixList(t, eolFindings(), m)
	for _, want := range []string{
		"daty wsparcia z endoflife.date z 2026-11-14.",
		"Niewspierana wersja nginx 1.24 na shop.example.com:443",
		"Wsparcie dla nginx 1.24 skończyło się 2024-04-23. Luki wykryte w tej wersji od tego czasu nie są naprawiane.",
		"Zaktualizuj do wspieranej wersji: najbliższa to `1.30.6`, najnowsza `1.31.8`.",
		"Wkrótce koniec wsparcia dla PHP 8.2 na shop.example.com:443",
		"Wsparcie dla PHP 8.2 kończy się 2026-12-31.",
		"Wsparcie dla Confluence 7.4 się skończyło.",
		"Według endoflife.date wsparcie dla nginx 1.24 skończyło się 2024-04-23.",
		"## Nadchodzące terminy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q:\n%s", want, out)
		}
	}
}

func TestComingUp(t *testing.T) {
	expires := now.Add(10 * 24 * time.Hour)
	tls := match.Finding{Key: "tls-expiring|www.example.com|443", Kind: match.KindTLSExpiring, Host: "www.example.com", Port: 443,
		Subject: "www.example.com", Expires: &expires, Score: 50, Severity: match.Medium, Confidence: match.ConfidenceObserved}
	php := eolFindings()[1]
	admin := findings()[3]
	later := findings()[2]
	fs := match.MarkAccepted([]match.Finding{tls, php, admin, later}, []match.Acceptance{
		accept([]match.Finding{admin}, "2026-12-01", "Only reachable over the VPN", "Jan"),
		// Beyond the next 90 days.
		accept([]match.Finding{later}, "2027-06-30", "Retired in June", "Jan"),
	}, now)
	out := fixList(t, fs, meta("en"))
	start := strings.Index(out, "## Coming up")
	if start < 0 {
		t.Fatalf("no coming up section:\n%s", out)
	}
	soon := out[start:]
	soon = soon[:strings.Index(soon, "\n\n## ")]
	want := []string{
		"- **2026-11-14** · TLS certificate expiring soon on www.example.com:443",
		"- **2026-12-01** · Acceptance ends: Jenkins admin interface reachable on ci.example.com:443",
		"- **2026-12-31** · PHP 8.2 support ending soon on shop.example.com:443",
	}
	lines := strings.Split(strings.TrimSpace(soon), "\n")[4:]
	if len(lines) != len(want) {
		t.Fatalf("coming up:\n%s", soon)
	}
	for i, w := range want {
		if !strings.HasPrefix(lines[i], w) {
			t.Errorf("line %d = %q, want it to start with %q", i, lines[i], w)
		}
	}
	// Nothing coming up, no section.
	if out := fixList(t, eolFindings()[:1], meta("en")); strings.Contains(out, "## Coming up") {
		t.Errorf("empty coming up section:\n%s", out)
	}
}

func TestEndOfSupportTextAndEffort(t *testing.T) {
	g := match.Groups(eolFindings()[:1])[0]
	why, todo := ItemText(g, "en")
	if why != "Support for nginx 1.24 ended on 2024-04-23. Flaws found in it since then are not fixed." ||
		todo != "Upgrade to a supported release: 1.30.6 is the closest, 1.31.8 the newest." {
		t.Errorf("ItemText = %q, %q", why, todo)
	}
	if title := ItemTitle(g, "en"); title != "nginx 1.24 past end of support on shop.example.com:443" {
		t.Errorf("title %q", title)
	}
	if e := Effort(g); e != 120 {
		t.Errorf("effort %d", e)
	}
	g.Category = "network"
	if e := Effort(g); e != 240 {
		t.Errorf("effort on a device %d", e)
	}
	// A mail server known by its greeting has no page to ask.
	g = match.Groups(eolFindings()[:1])[0]
	g.URL = "tcp://shop.example.com:25"
	if p := ProofOf(g, "en"); p.Command != "" || p.SeeIt != "Compare the version with https://endoflife.date/nginx." {
		t.Errorf("proof %+v", p)
	}
}
