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
