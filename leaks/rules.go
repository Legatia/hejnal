package leaks

import (
	"net"
	"regexp"
	"strings"
)

// Rule describes one kind of secret the scanner recognises.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// rule is a Rule plus what the scanner needs to find it.
type rule struct {
	Rule
	re *regexp.Regexp
	// group is the capture group that holds the secret.
	group int
	// keywords are lower-case strings, one of which must appear in a line,
	// in any case, before re is tried. They keep scanning fast.
	keywords []string
	// minEntropy is the lowest Shannon entropy, in bits per character, that
	// a secret may have. Zero turns the check off.
	minEntropy float64
	// prefixes are fixed, public starts of the secret, such as "ghp_",
	// longest first. Redaction shows the prefix plus 2 characters.
	prefixes []string
	// check, when set, sees the whole line and match and can reject it.
	check func(line string, m []int) bool
	// pem marks the private key rule. re matches the header, and the secret
	// is the key data on the lines that follow it.
	pem bool
	// random marks secrets that are random strings without a fixed prefix,
	// so that placeholder words count anywhere in them, as in tokens.
	random bool
}

// Rules lists the built-in rules in the order they are applied.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = r.Rule
	}
	return out
}

// tokenEnd matches the character after a token, or the end of the line, so a
// match cannot stop in the middle of a longer token.
const tokenEnd = `(?:[^0-9A-Za-z_\-]|$)`

// tokenStart matches the start of the line or a character that cannot be
// part of the token, including "_", as in MY_KEY_AKIA....
const tokenStart = `(?:^|[^0-9A-Za-z])`

// rules go from specific formats to general ones. When two rules find the
// same secret in a file, the first one is reported.
var rules = []rule{{
	Rule:     Rule{"aws-access-key-id", "AWS access key ID", SeverityHigh},
	re:       regexp.MustCompile(tokenStart + `((?:AKIA|ASIA)[0-9A-Z]{16})(?:[^0-9A-Za-z]|$)`),
	group:    1,
	keywords: []string{"akia", "asia"},
	prefixes: []string{"AKIA", "ASIA"},
}, {
	Rule:     Rule{"aws-secret-access-key", "AWS secret access key", SeverityCritical},
	re:       regexp.MustCompile(`(?i)(?:aws[_.\-]?)?secret[_.\-]?(?:access[_.\-]?)?key["']?\s*(?::=|=>|=|:)\s*["']?([0-9A-Za-z/+]{40})(?:[^0-9A-Za-z/+=]|$)`),
	group:    1,
	keywords: []string{"secret"},
	random:   true,
}, {
	Rule:     Rule{"github-token", "GitHub token", SeverityCritical},
	re:       regexp.MustCompile(tokenStart + `(gh[pousr]_[0-9A-Za-z]{36,251})(?:[^0-9A-Za-z_]|$)`),
	group:    1,
	keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
	prefixes: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
}, {
	Rule:     Rule{"github-fine-grained-token", "GitHub fine-grained personal access token", SeverityCritical},
	re:       regexp.MustCompile(`\b(github_pat_[0-9A-Za-z_]{82})\b`),
	group:    1,
	keywords: []string{"github_pat_"},
	prefixes: []string{"github_pat_"},
}, {
	Rule:     Rule{"gitlab-token", "GitLab personal access token", SeverityCritical},
	re:       regexp.MustCompile(`\b(glpat-[0-9A-Za-z_\-]{20,})`),
	group:    1,
	keywords: []string{"glpat-"},
	prefixes: []string{"glpat-"},
}, {
	Rule:     Rule{"slack-token", "Slack token", SeverityHigh},
	re:       regexp.MustCompile(tokenStart + `(xox[abposr]-[0-9]{1,16}-[0-9A-Za-z\-]{8,}|xoxe(?:\.xox[bp])?-[0-9]-[0-9A-Za-z\-]{20,}|xapp-[0-9]-[0-9A-Za-z\-]{20,})`),
	group:    1,
	keywords: []string{"xox", "xapp-"},
	prefixes: []string{"xoxe.xoxb-", "xoxe.xoxp-", "xoxa-", "xoxb-", "xoxe-", "xoxo-", "xoxp-", "xoxr-", "xoxs-", "xapp-"},
}, {
	Rule:     Rule{"slack-webhook", "Slack incoming webhook or workflow trigger URL", SeverityHigh},
	re:       regexp.MustCompile(`(https?://hooks\.slack\.com/(?:services/T[0-9A-Z]{6,12}/B[0-9A-Z]{6,12}/[0-9A-Za-z]{20,32}|(?:triggers|workflows)/T[0-9A-Z]{6,12}/[0-9A-Za-z]{6,24}/[0-9A-Za-z]{20,64}))\b`),
	group:    1,
	keywords: []string{"hooks.slack.com"},
	prefixes: []string{"https://hooks.slack.com/services/", "https://hooks.slack.com/triggers/", "https://hooks.slack.com/workflows/",
		"http://hooks.slack.com/services/", "http://hooks.slack.com/triggers/", "http://hooks.slack.com/workflows/"},
}, {
	Rule:     Rule{"stripe-live-key", "Stripe live secret or restricted key", SeverityCritical},
	re:       regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`),
	group:    1,
	keywords: []string{"_live_"},
	prefixes: []string{"sk_live_", "rk_live_"},
}, {
	Rule:     Rule{"google-api-key", "Google API key", SeverityHigh},
	re:       regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})` + tokenEnd),
	group:    1,
	keywords: []string{"aiza"},
	prefixes: []string{"AIza"},
}, {
	Rule:     Rule{"google-oauth-client-secret", "Google OAuth client secret", SeverityHigh},
	re:       regexp.MustCompile(`\b(GOCSPX-[0-9A-Za-z_\-]{28})` + tokenEnd),
	group:    1,
	keywords: []string{"gocspx-"},
	prefixes: []string{"GOCSPX-"},
}, {
	Rule:       Rule{"private-key", "Private key (PEM, SSH2 or PuTTY file with key data)", SeverityCritical},
	re:         regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?)-----|---- BEGIN (SSH2 (?:ENCRYPTED )?PRIVATE KEY) ----|^(PuTTY-User-Key-File-[23]): `),
	group:      1,
	keywords:   []string{"private key", "putty-user-key-file"},
	minEntropy: 4,
	pem:        true,
}, {
	Rule:     Rule{"npm-token", "npm access token", SeverityCritical},
	re:       regexp.MustCompile(`\b(npm_[0-9A-Za-z]{36})\b`),
	group:    1,
	keywords: []string{"npm_"},
	prefixes: []string{"npm_"},
}, {
	Rule:     Rule{"pypi-token", "PyPI API token", SeverityCritical},
	re:       regexp.MustCompile(`\b(pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,})`),
	group:    1,
	keywords: []string{"pypi-"},
	prefixes: []string{"pypi-"},
}, {
	Rule:     Rule{"sendgrid-api-key", "SendGrid API key", SeverityHigh},
	re:       regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})` + tokenEnd),
	group:    1,
	keywords: []string{"sg."},
	prefixes: []string{"SG."},
}, {
	Rule:     Rule{"twilio-api-key", "Twilio API key", SeverityHigh},
	re:       regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`),
	group:    1,
	keywords: []string{"sk"},
	prefixes: []string{"SK"},
}, {
	Rule:     Rule{"mailgun-api-key", "Mailgun API key", SeverityHigh},
	re:       regexp.MustCompile(`\b(key-[0-9a-fA-F]{32})\b`),
	group:    1,
	keywords: []string{"key-"},
	prefixes: []string{"key-"},
}, {
	Rule:     Rule{"azure-storage-key", "Azure Storage account key in a connection string", SeverityCritical},
	re:       regexp.MustCompile(`(?i:AccountKey)\s*=\s*([0-9A-Za-z+/]{86}==)`),
	group:    1,
	keywords: []string{"accountkey"},
	random:   true,
}, {
	Rule:     Rule{"telegram-bot-token", "Telegram bot token", SeverityHigh},
	re:       regexp.MustCompile(`\b([0-9]{8,10}:A[0-9A-Za-z_\-]{34})` + tokenEnd),
	group:    1,
	keywords: []string{":a"},
}, {
	Rule:     Rule{"openai-api-key", "OpenAI API key", SeverityHigh},
	re:       regexp.MustCompile(`\b(sk-(?:proj|svcacct|admin)-[0-9A-Za-z_\-]{32,}|sk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20})` + tokenEnd),
	group:    1,
	keywords: []string{"sk-proj-", "sk-svcacct-", "sk-admin-", "t3blbkfj"},
	prefixes: []string{"sk-svcacct-", "sk-admin-", "sk-proj-", "sk-"},
}, {
	Rule:     Rule{"anthropic-api-key", "Anthropic API key", SeverityHigh},
	re:       regexp.MustCompile(`\b(sk-ant-(?:api03|admin01)-[0-9A-Za-z_\-]{32,})` + tokenEnd),
	group:    1,
	keywords: []string{"sk-ant-"},
	prefixes: []string{"sk-ant-admin01-", "sk-ant-api03-"},
}, {
	Rule:     Rule{"password-in-url", "Password in a URL (scheme://user:password@host)", SeverityHigh},
	re:       regexp.MustCompile(`\b([A-Za-z][0-9A-Za-z+.\-]{1,30})://([^\s:@/"'<>]{1,128}):([^\s@/"'<>]{3,256})@([0-9A-Za-z.\-]{1,253}|\[[0-9A-Fa-f:.]+\])`),
	group:    3,
	keywords: []string{"://"},
	check:    realURLPassword,
}, {
	Rule:       Rule{"generic-secret", "Password, secret or token assigned a literal value", SeverityMedium},
	re:         regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api_?key|secret_?key|private_?key|access_?key)["']?\s*(?::=|=>|=|:)\s*["'\x60]([^"'\x60\s]{8,200})["'\x60]`),
	group:      1,
	keywords:   []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "privatekey", "access_key", "accesskey"},
	minEntropy: 3.5,
	check:      notVariableName,
}, {
	// Settings files such as .env and YAML write values without quotes.
	Rule: Rule{"env-secret", "Password, secret or token in a settings file", SeverityMedium},
	re: regexp.MustCompile(`(?i)^\s*(?:export\s+)?[0-9A-Za-z_.\-]*(?:password|passwd|secret|token|api_?key|secret_?key|private_?key|access_?key)\s*[=:]\s*` +
		`([^\s"'\x60#(){}$<>!&*|][^\s"'\x60#(){}$<>]{7,199})\s*(?:#.*)?$`),
	group:      1,
	keywords:   []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "privatekey", "access_key", "accesskey"},
	minEntropy: 3.5,
	check:      notVariableName,
}}

var variableName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+[=:]?$`)

// notVariableName rejects values that name an environment variable, such as
// "DB_PASSWORD" or "GITHUB_TOKEN=", rather than hold a secret.
func notVariableName(line string, m []int) bool {
	return !variableName.MatchString(line[m[2]:m[3]])
}

// realURLPassword rejects URL passwords that refer to variables or are
// masked, and URLs that point at loopback or documentation hosts.
func realURLPassword(line string, m []int) bool {
	pass := line[m[6]:m[7]]
	if strings.HasPrefix(pass, "$") || strings.HasPrefix(pass, "%") || strings.Trim(pass, "*") == "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(strings.Trim(line[m[8]:m[9]], "[]")), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	for _, d := range []string{"example.com", "example.org", "example.net"} {
		if host == d || strings.HasSuffix(host, "."+d) {
			return false
		}
	}
	for _, tld := range []string{".example", ".test", ".invalid"} {
		if strings.HasSuffix(host, tld) {
			return false
		}
	}
	return true
}
