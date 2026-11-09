package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Legatia/hejnal/match"
)

func kevGroup(fs ...match.Finding) match.Group {
	for i := range fs {
		fs[i].Kind, fs[i].Host, fs[i].Port = match.KindKEV, "vpn.example.com", 443
		fs[i].URL, fs[i].Technology, fs[i].TechID = "https://vpn.example.com/remote/login", "FortiGate SSL VPN", "fortigate"
		fs[i].Evidence = "login page /remote/login"
		if fs[i].ListedBy == nil {
			fs[i].ListedBy = []string{match.ListCISA}
		}
	}
	return match.Groups(fs)[0]
}

func TestProof(t *testing.T) {
	confirmed := kevGroup(match.Finding{CVE: "CVE-2024-21762", Version: "7.2.4", Confidence: match.ConfidenceVersion, DateAdded: "2024-02-09", Score: 90})
	p := ProofOf(confirmed, "en")
	if p.Verdict != VerdictConfirmed || len(p.Steps) != 4 || !strings.Contains(p.Steps[2].Text, "CVE-2024-21762") || !strings.Contains(p.Steps[3].Text, "2024-02-09") {
		t.Errorf("confirmed: %+v", p)
	}
	if p.Command != "curl -sk -D - -o /dev/null 'https://vpn.example.com/remote/login'" {
		t.Errorf("command = %q", p.Command)
	}
	for _, s := range p.Steps {
		if !s.OK {
			t.Errorf("an unchecked step in a confirmed item: %+v", s)
		}
	}

	noVersion := kevGroup(match.Finding{CVE: "CVE-2024-21762", Confidence: match.ConfidenceProduct, ListedBy: []string{match.ListCISA, match.ListENISA}, DateAdded: "2024-02-09"})
	if p := ProofOf(noVersion, "en"); p.Verdict != VerdictLikely || p.Steps[1].OK || !strings.Contains(p.Steps[2].Text, "ENISA") {
		t.Errorf("no version: %+v", p)
	}
	packaged := kevGroup(match.Finding{CVE: "CVE-2023-38408", Version: "8.9p1", Packaged: true, Confidence: match.ConfidenceProduct})
	if p := ProofOf(packaged, "en"); p.Verdict != VerdictCheck || !strings.Contains(p.Summary, "Check it") {
		t.Errorf("packaged: %+v", p)
	}
	if p := ProofOf(packaged, "pl"); !strings.Contains(p.Summary, "Do sprawdzenia") {
		t.Errorf("Polish: %+v", p)
	}

	foreign := match.Groups([]match.Finding{{Kind: match.KindExposedFile, TechID: "foreign-host", Host: "old.example.com", Port: 443, URL: "https://old.example.com/",
		Evidence: "its certificate names none of the domains in your scope; it names www.someone-else.com", Score: 55}})[0]
	if p := ProofOf(foreign, "en"); !strings.HasPrefix(p.Command, "openssl s_client -connect 'old.example.com:443' -servername 'old.example.com'") ||
		p.Verdict != VerdictCheck || len(p.Steps) != 2 || !p.Steps[0].OK || !strings.HasSuffix(p.Steps[0].Text, "(www.someone-else.com).") || p.Steps[1].OK {
		t.Errorf("foreign host: %+v", p)
	}
	mail := match.Groups([]match.Finding{{Kind: match.KindEmail, TechID: "dmarc-missing", Host: "example.com", Score: 50}})[0]
	if p := ProofOf(mail, "en"); p.Command != "dig +short TXT 'example.com'; dig +short TXT '_dmarc.example.com'" {
		t.Errorf("mail: %+v", p)
	}
	// Nothing from a scanned system reaches a command unquoted.
	evil := match.Groups([]match.Finding{{Kind: match.KindTakeover, Host: "x';rm -rf ~;'.example.com", Score: 80}})[0]
	if p := ProofOf(evil, "en"); p.Command != "" {
		t.Errorf("unsafe name in a command: %q", p.Command)
	}
	odd := kevGroup(match.Finding{CVE: "CVE-1", Confidence: match.ConfidenceProduct})
	odd.URL = "https://vpn.example.com/a'b c"
	if p := ProofOf(odd, "en"); p.Command != "curl -sk -D - -o /dev/null 'https://vpn.example.com/a%27b%20c'" {
		t.Errorf("quoted path: %q", p.Command)
	}
	secret := match.Groups([]match.Finding{{Kind: match.KindSecret, Technology: "Stripe secret key", File: "app/.env", Line: 3, Fingerprint: "ab", Score: 90}})[0]
	if p := ProofOf(secret, "en"); p.Verdict != VerdictLikely || !strings.Contains(p.SeeIt, "app/.env:3") {
		t.Errorf("secret: %+v", p)
	}
}

func TestFixListShowsProof(t *testing.T) {
	g := kevGroup(match.Finding{CVE: "CVE-2024-21762", Version: "7.2.4", Confidence: match.ConfidenceVersion, DateAdded: "2024-02-09", Score: 90, Severity: match.Critical})
	var b strings.Builder
	if err := FixList(&b, g.Findings, Meta{Organization: "Acme", Lang: "en", Services: 1}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"**How sure:** Confirmed", "  - ✓ NVD lists version 7.2.4", "**See it yourself:**", "`curl -sk -D - -o /dev/null 'https://vpn.example.com/remote/login'`"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("fix list lacks %q:\n%s", want, b.String())
		}
	}
}

// safeCommand matches the commands Hejnal prints: fixed words and quoted
// arguments made only of characters that mean nothing to a shell.
var safeCommand = regexp.MustCompile(`^(?:curl -sk -D - -o /dev/null 'https?://[A-Za-z0-9.\-_\[\]:]+/[A-Za-z0-9\-._~/%]*'` +
	`|openssl s_client -connect '[A-Za-z0-9.\-_]+:[0-9]+' -servername '[A-Za-z0-9.\-_]+' </dev/null 2>/dev/null \| openssl x509 -noout -subject -ext subjectAltName -enddate` +
	`|dig \+short (?:TXT )?'[A-Za-z0-9.\-_]+'(?:; dig \+short TXT '[A-Za-z0-9.\-_]+')*)$`)

// A scanned server chooses where it redirects to, so the URL in an item can
// hold anything. No output may turn it into a command that does more than
// it says, and Markdown must show the command exactly.
func TestCommandsSurviveHostileInput(t *testing.T) {
	hostile := []string{
		"https://vpn.example.com/login?next=`;touch /tmp/x;`",
		"https://vpn.example.com/a`id`b/$(id)/'x'/\"y\"/;|&<>*?",
		"https://vpn.example.com:8443/%27%60%3B/x y\\z",
		"https://vpn.example.com/login#`;id;`",
		"https://vpn.example.com/<script>alert(1)</script>",
		"https://[2001:db8::1]:8443/a`b",
	}
	for _, raw := range hostile {
		var fs []match.Finding
		for i, kind := range []match.Kind{match.KindKEV, match.KindAdminExposed, match.KindExposedFile} {
			fs = append(fs, match.Finding{Key: fmt.Sprintf("%s|vpn.example.com|443|%d", kind, i), Kind: kind, Host: "vpn.example.com", Port: 443,
				URL: raw, TechID: "fortinet-fortigate", Technology: "FortiGate `x`", CVE: "CVE-2024-21762", Evidence: "title `;id;` <i class=x>",
				DateAdded: "2024-02-09", ListedBy: []string{match.ListCISA}, Score: 90, Severity: match.Critical, Confidence: match.ConfidenceProduct})
		}
		fs[2].TechID = "env"
		var commands []string
		for _, g := range match.Groups(fs) {
			p := ProofOf(g, "en")
			if p.Command == "" {
				continue
			}
			if !safeCommand.MatchString(p.Command) {
				t.Errorf("%s: unsafe command %q", raw, p.Command)
			}
			// JSON carries the same command.
			js, _ := json.Marshal(p)
			var back Proof
			if json.Unmarshal(js, &back); back.Command != p.Command {
				t.Errorf("JSON changed the command: %q", back.Command)
			}
			commands = append(commands, p.Command)
		}
		if len(commands) != 3 {
			t.Errorf("%s: commands %q", raw, commands)
		}
		var b strings.Builder
		if err := FixList(&b, fs, Meta{Organization: "Acme", Lang: "en", Services: 1}); err != nil {
			t.Fatal(err)
		}
		for _, c := range commands {
			if !strings.Contains(b.String(), " `"+c+"`\n") {
				t.Errorf("%s: the fix list does not show %q verbatim:\n%s", raw, c, b.String())
			}
		}
		for _, l := range strings.Split(b.String(), "\n") {
			if strings.Contains(l, "curl ") && (strings.Contains(l, "`;") || strings.Count(l, "`") != 2) {
				t.Errorf("%s: fix list line %q", raw, l)
			}
		}
		b.Reset()
		if err := Overview(&b, fs, Meta{Organization: "Acme", Lang: "en", Services: 1}, OverviewOptions{}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "<script>alert") || strings.Contains(b.String(), "<i class=x>") {
			t.Errorf("%s: the overview shows markup from the scanned server", raw)
		}
		if s := Summary(fs, fs, nil, false, Meta{Organization: "Acme", Lang: "en"}); strings.Contains(s, "<script>") {
			t.Errorf("%s: the chat summary shows markup: %q", raw, s)
		}
	}
	// Names that are not plain host names never reach a command.
	for _, host := range []string{"x';id;'.example.com", "a b.example.com", "x`id`.example.com", "x$(id).example.com"} {
		for _, f := range []match.Finding{
			{Kind: match.KindTakeover, Host: host, Score: 80},
			{Kind: match.KindEmail, TechID: "dmarc-missing", Host: host, Score: 50},
			{Kind: match.KindTLSExpired, Host: host, Port: 443, Score: 70},
			{Kind: match.KindExposedFile, TechID: "foreign-host", Host: host, Port: 443, URL: "https://" + host + "/", Score: 55},
			{Kind: match.KindKEV, Host: host, Port: 443, URL: "https://" + host + "/", CVE: "CVE-1", Score: 90},
		} {
			if p := ProofOf(match.Groups([]match.Finding{f})[0], "en"); p.Command != "" {
				t.Errorf("%s %s: command %q", f.Kind, host, p.Command)
			}
		}
	}
	if got := mdCommand("echo `x` ``y``"); got != "``` echo `x` ``y`` ```" {
		t.Errorf("mdCommand = %q", got)
	}
	if mdCommand("a\nb") != "" {
		t.Error("a command with a line break was shown")
	}
}
