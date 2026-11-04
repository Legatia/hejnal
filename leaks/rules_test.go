package leaks

import (
	"fmt"
	"strings"
	"testing"
)

const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	hexdig  = "0123456789abcdef"
	alnum   = upper + lower + digits
	urlsafe = alnum + "-_"
	b64     = alnum + "+/"
)

// fake returns n characters from alphabet in a fixed pseudo-random order,
// skipping any result that contains a placeholder word by chance. Tests build
// every fake secret at run time from pieces like this, so that no source
// file holds a complete token for secret scanners such as GitHub's to flag.
func fake(alphabet string, n int, seed uint32) string {
	x := seed*2654435761 | 1
	for {
		b := make([]byte, n)
		for i := range b {
			x ^= x << 13
			x ^= x >> 17
			x ^= x << 5
			b[i] = alphabet[x%uint32(len(alphabet))]
		}
		if s := string(b); !placeholder(s) {
			return s
		}
	}
}

type ruleCase struct {
	rule, line, secret string
}

// ruleCases gives at least one line per rule, except private keys, which
// span several lines and have their own tests. Each line holds one secret.
func ruleCases() []ruleCase {
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	ghs := "ghs_" + fake(alnum, 36, 1)
	akia := "AKIA" + fake(upper+digits, 16, 2)
	asia := "ASIA" + fake(upper+digits, 16, 3)
	awsSecret, awsSecret2 := fake(b64, 40, 4), fake(b64, 40, 5)
	fineGrained := "github_pat_" + fake(alnum, 22, 6) + "_" + fake(alnum, 59, 7)
	glpat := "glpat-" + fake(urlsafe, 20, 8)
	xoxb := "xoxb-" + fake(digits, 11, 9) + "-" + fake(digits, 12, 10) + "-" + fake(alnum, 24, 11)
	hook := "https://hooks.slack.com/services/T" + fake(upper+digits, 10, 12) + "/B" + fake(upper+digits, 10, 13) + "/" + fake(alnum, 24, 14)
	skLive := "sk_live_" + fake(alnum, 24, 15)
	rkLive := "rk_live_" + fake(alnum, 99, 16)
	aiza := "AIza" + fake(urlsafe, 35, 17)
	gocspx := "GOCSPX-" + fake(urlsafe, 28, 18)
	npm := "npm_" + fake(alnum, 36, 19)
	pypi := "pypi-AgEIcHlwaS5vcmc" + fake(urlsafe, 60, 20)
	sendgrid := "SG." + fake(urlsafe, 22, 21) + "." + fake(urlsafe, 43, 22)
	twilio := "SK" + fake(hexdig, 32, 23)
	mailgun := "key-" + fake(hexdig, 32, 24)
	azure := fake(b64, 86, 25) + "=="
	telegram := fake(digits, 10, 26) + ":AA" + fake(urlsafe, 33, 27)
	openai := "sk-proj-" + fake(urlsafe, 120, 28)
	openaiLegacy := "sk-" + fake(alnum, 20, 29) + "T3BlbkFJ" + fake(alnum, 20, 30)
	anthropic := "sk-ant-api03-" + fake(urlsafe, 93, 31) + "AA"
	urlPassword := fake(alnum, 16, 32)
	generic := "Rk8vW2" + "qN5tJ9" + "pL4z"
	generic2 := "Zx3Cv6" + "Bn9Mq2Wd5"

	return []ruleCase{
		{"aws-access-key-id", "aws_access_key_id = " + akia, akia},
		{"aws-access-key-id", "export AWS_ACCESS_KEY_ID=" + asia, asia},
		{"aws-secret-access-key", "aws_secret_access_key = " + awsSecret, awsSecret},
		{"aws-secret-access-key", `"SecretAccessKey": "` + awsSecret2 + `",`, awsSecret2},
		{"github-token", "GH_TOKEN: " + ghp, ghp},
		// The password-in-url rule finds the same secret; the first rule wins.
		{"github-token", "git clone https://x-access-token:" + ghs + "@github.com/acme/app.git", ghs},
		{"github-fine-grained-token", "token " + fineGrained, fineGrained},
		{"gitlab-token", "GITLAB_TOKEN=" + glpat, glpat},
		{"slack-token", "slack: " + xoxb, xoxb},
		{"slack-webhook", "webhook: " + hook, hook},
		{"stripe-live-key", "STRIPE_KEY=" + skLive, skLive},
		{"stripe-live-key", "stripe.api_key = " + rkLive, rkLive},
		{"google-api-key", "const key = '" + aiza + "';", aiza},
		{"google-oauth-client-secret", "client_secret: " + gocspx, gocspx},
		{"npm-token", "//registry.npmjs.org/:_authToken=" + npm, npm},
		{"pypi-token", "password = " + pypi, pypi},
		{"sendgrid-api-key", "SENDGRID_API_KEY=" + sendgrid, sendgrid},
		{"twilio-api-key", "twilio_key: " + twilio, twilio},
		{"mailgun-api-key", "MAILGUN=" + mailgun, mailgun},
		{"azure-storage-key", "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=" + azure + ";EndpointSuffix=core.windows.net", azure},
		{"telegram-bot-token", fmt.Sprintf("bot = Bot(%q)", telegram), telegram},
		{"openai-api-key", "OPENAI_API_KEY=" + openai, openai},
		{"openai-api-key", "openai.api_key = " + openaiLegacy, openaiLegacy},
		{"anthropic-api-key", "ANTHROPIC_API_KEY=" + anthropic, anthropic},
		{"password-in-url", "DATABASE_URL=postgres://app:" + urlPassword + "@db.internal.acme.pl:5432/app", urlPassword},
		{"generic-secret", `db_password = "` + generic + `"`, generic},
		{"generic-secret", `"api_key": "` + generic2 + `",`, generic2},
	}
}

func TestRules(t *testing.T) {
	for _, c := range ruleCases() {
		t.Run(c.rule, func(t *testing.T) {
			leaks, err := ScanReader("cfg/app.env", strings.NewReader("first line\n"+c.line+"\n"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(leaks) != 1 {
				t.Fatalf("got %d leaks, want 1: %+v", len(leaks), leaks)
			}
			l := leaks[0]
			if l.RuleID != c.rule || l.File != "cfg/app.env" || l.Line != 2 || l.Fingerprint != fingerprint(c.secret) {
				t.Errorf("got %+v, want rule %s on line 2 with the secret's fingerprint", l, c.rule)
			}
			if l.Severity == "" || l.Description == "" || l.Commit != "" {
				t.Errorf("got %+v, want a severity and a description and no commit", l)
			}
		})
	}
}

func TestEveryRuleIsTested(t *testing.T) {
	tested := map[string]bool{"private-key": true} // see TestPrivateKeys
	for _, c := range ruleCases() {
		tested[c.rule] = true
	}
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("rule %s is listed twice", r.ID)
		}
		seen[r.ID] = true
		if !tested[r.ID] {
			t.Errorf("rule %s has no test case", r.ID)
		}
		switch r.Severity {
		case SeverityCritical, SeverityHigh, SeverityMedium:
		default:
			t.Errorf("rule %s has severity %q", r.ID, r.Severity)
		}
	}
}

func TestPlaceholdersAndAllowMarker(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	pw := fake(alnum, 16, 50)
	for _, line := range []string{
		"aws_access_key_id = " + "AKIA" + "IOSFODNN7" + "EXAMPLE",
		"key: AKIA" + strings.Repeat("0", 16),
		"STRIPE_KEY=sk_live_" + "Test" + fake(alnum, 24, 51),
		"token: ghp_" + strings.Repeat("x", 36),
		"token: ghp_" + "Sample" + fake(alnum, 30, 52),
		"token: ghp_" + "dummy" + fake(alnum, 31, 53),
		"token: ghp_" + "FAKE" + fake(alnum, 32, 54),
		"AccountKey=" + "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/" + "K1SZFPTOtr/KBHBeksoGMGw==",
		`password = "changeme-` + pw + `"`,
		`password = "your_` + pw + `"`,
		`password = "${DB_PASSWORD}"`,
		`api_key = "<your-api-key>"`,
		`token = "{{.Values.apiToken}}"`,
		`password = "aaaaaaaabbbbbbbb"`,     // too little entropy
		`secret := "SLACK_BOT_TOKEN_PROD="`, // a variable name
		`if password == "` + pw + `" {`,     // a comparison, not an assignment
		"postgres://user:password@db.acme.pl/app",
		"postgres://user:${DB_PASS}@db.acme.pl/app",
		"postgres://app:" + pw + "@localhost:5432/app",
		"mysql://root:" + pw + "@127.0.0.1/app",
		"https://admin:" + pw + "@api.example.com/v1",
		"-----BEGIN " + "RSA PRIVATE KEY-----", // a header without key data
		"GITHUB_TOKEN=" + ghp + " # hejnal:allow",
	} {
		leaks, err := ScanReader("x", strings.NewReader(line), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(leaks) != 0 {
			t.Errorf("%q: got %+v, want no leaks", line, leaks)
		}
	}

	// The marker covers only its own line.
	leaks, _ := ScanReader("x", strings.NewReader("# hejnal:allow\nGITHUB_TOKEN="+ghp+"\n"), Options{})
	if len(leaks) != 1 || leaks[0].Line != 2 {
		t.Errorf("got %+v, want the token on line 2", leaks)
	}
}

func TestPlaceholder(t *testing.T) {
	for _, w := range []string{"EXAMPLE", "Sample", "dummy", "FAKE", "test", "xXxX", "00000000", "YOUR_", "ChangeMe", "<key>", "${KEY}", "{{ key }}"} {
		if s := "Ab3" + w + "Zq9"; !placeholder(s) {
			t.Errorf("placeholder(%q) = false", s)
		}
	}
	for _, s := range []string{fake(alnum, 40, 60), "0000000", "Password1!"} {
		if placeholder(s) {
			t.Errorf("placeholder(%q) = true", s)
		}
	}
}
