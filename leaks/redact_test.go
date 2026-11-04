package leaks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	for _, tt := range []struct {
		secret   string
		prefixes []string
		want     string
	}{
		{"ghp_" + strings.Repeat("ab", 18), []string{"ghp_"}, "ghp_ab… (40 chars)"},
		{"github_pat_" + strings.Repeat("1A", 41), []string{"github_pat_"}, "github_pat_1A… (93 chars)"},
		// Without a known public prefix, nothing of the secret is shown.
		{"abcdefghijklmnopqrstuvwx", nil, "… (24 chars)"},
		{"abc", nil, "… (3 chars)"},
		{"żółwżółwżółwżółw", nil, "… (16 chars)"},
		{"abcdefghijklmnop", []string{"zz"}, "… (16 chars)"}, // prefix does not apply
		{"ghp_ab", []string{"ghp_"}, "ghp… (6 chars)"},       // never more than half
	} {
		if got := redact(tt.secret, tt.prefixes); got != tt.want {
			t.Errorf("redact(%q) = %q, want %q", tt.secret, got, tt.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a1B2", 9)
	key := []byte("installation key")
	m := hmac.New(sha256.New, key)
	m.Write([]byte(secret))
	want := hex.EncodeToString(m.Sum(nil))[:16]
	leaks, _ := ScanReader("x", strings.NewReader("token: "+secret), Options{FingerprintKey: key})
	if len(leaks) != 1 || leaks[0].Fingerprint != want {
		t.Fatalf("got %+v, want fingerprint %s", leaks, want)
	}
	if leaks[0].Redacted != "ghp_a1… (40 chars)" {
		t.Errorf("Redacted = %q", leaks[0].Redacted)
	}
	// Without the key, a fingerprint cannot be checked against guesses: it
	// is not the plain hash, and another key gives another fingerprint.
	sum := sha256.Sum256([]byte(secret))
	other, _ := ScanReader("x", strings.NewReader("token: "+secret), Options{FingerprintKey: []byte("another key")})
	if want == hex.EncodeToString(sum[:])[:16] || other[0].Fingerprint == want {
		t.Error("fingerprints are not keyed")
	}
}

// pemKey builds a private key block around random key data. It returns the
// block and the key data on one line.
func pemKey(kind string, seed uint32) (block, data string) {
	var lines []string
	for i := range uint32(6) {
		lines = append(lines, fake(alnum+"/", 64, seed+i))
	}
	lines = append(lines, fake(alnum+"/", 20, seed+9)+"==")
	begin, end := "-----BEGIN "+kind+"-----", "-----END "+kind+"-----"
	return begin + "\n" + strings.Join(lines, "\n") + "\n" + end + "\n", strings.Join(lines, "")
}

func TestLeaksNeverContainSecrets(t *testing.T) {
	cases := ruleCases()
	var text strings.Builder
	var secrets []string
	for _, c := range cases {
		text.WriteString(c.line + "\n")
		secrets = append(secrets, c.secret)
	}
	block, data := pemKey("RSA PRIVATE KEY", 70)
	text.WriteString(block)
	secrets = append(secrets, data)

	leaks, err := ScanReader("all.env", strings.NewReader(text.String()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaks) != len(secrets) {
		t.Fatalf("got %d leaks, want %d", len(leaks), len(secrets))
	}
	js, err := json.Marshal(leaks)
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprintf("%+v\n%#v\n%s", leaks, leaks, js)
	for i, s := range secrets {
		if strings.Contains(out, s) || strings.Contains(out, s[len(s)-12:]) {
			t.Errorf("secret %d (%s) appears in the output", i, redact(s, nil))
		}
	}
}

func TestPrivateKeys(t *testing.T) {
	for i, kind := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY",
		"PGP PRIVATE KEY BLOCK", "ENCRYPTED PRIVATE KEY", "PRIVATE KEY"} {
		block, data := pemKey(kind, uint32(100+10*i))
		leaks, err := ScanReader("id", strings.NewReader("# deploy key\n"+block+"after\n"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(leaks) != 1 || leaks[0].RuleID != "private-key" || leaks[0].Line != 2 || leaks[0].Fingerprint != fingerprint(nil, data) {
			t.Errorf("%s: got %+v, want one private key on line 2", kind, leaks)
		}
	}

	block, data := pemKey("RSA PRIVATE KEY", 200)
	lines := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	for name, text := range map[string]string{
		// The same key pasted into one JSON string has the same fingerprint.
		"json": `{"type": "service_account", "private_key": "` + strings.Join(lines, `\n`) + `\n"}`,
		// Encrypted PEM keys have header fields before the key data.
		"encrypted": lines[0] + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D\n\n" + strings.Join(lines[1:], "\n"),
		// Key data in quoted strings, as in source code.
		"quoted": "const key = `" + lines[0] + "\n" + `"` + strings.Join(lines[1:len(lines)-1], `\n" +`+"\n"+`"`) + `\n"`,
	} {
		leaks, _ := ScanReader("k", strings.NewReader(text), Options{})
		if len(leaks) != 1 || leaks[0].Line != 1 || leaks[0].Fingerprint != fingerprint(nil, data) {
			t.Errorf("%s: got %+v, want the key on line 1 with the key data's fingerprint", name, leaks)
		}
		if len(leaks) == 1 && leaks[0].Redacted != fmt.Sprintf("… (%d chars)", len(data)) {
			t.Errorf("%s: Redacted = %q", name, leaks[0].Redacted)
		}
	}

	begin, end := "-----BEGIN "+"PRIVATE KEY-----", "-----END "+"PRIVATE KEY-----"
	for name, text := range map[string]string{
		"header in code": `if strings.HasPrefix(s, "` + begin + `") {`,
		"excerpt":        begin + "\nMIIEvQIBADANBgkqhkiG...\n" + end,
		"filler":         begin + "\n" + strings.Repeat("X", 64) + "\n" + strings.Repeat("X", 64) + "\n" + end,
		"allowed":        begin + " hejnal:allow\n" + strings.Join(lines[1:], "\n"),
	} {
		if leaks, _ := ScanReader("k", strings.NewReader(text), Options{}); len(leaks) != 0 {
			t.Errorf("%s: got %+v, want no leaks", name, leaks)
		}
	}

	// A secret right after a header without key data is still found.
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	leaks, _ := ScanReader("k", strings.NewReader(begin+"\nGITHUB_TOKEN="+ghp+"\n"), Options{})
	if len(leaks) != 1 || leaks[0].RuleID != "github-token" {
		t.Errorf("got %+v, want the GitHub token", leaks)
	}
}

func TestDuplicates(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	xoxb := "xoxb-" + fake(digits, 11, 300) + "-" + fake(digits, 12, 301) + "-" + fake(alnum, 24, 302)
	text := "a\nGH=" + ghp + "\nb\nc\nagain: " + ghp + "\n" +
		// Two rules match the same secret here; the first is reported.
		`SLACK_TOKEN = "` + xoxb + `"` + "\n"
	leaks, err := ScanReader("f", strings.NewReader(text), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaks) != 2 || leaks[0].Line != 2 || leaks[1].RuleID != "slack-token" || leaks[1].Line != 6 {
		t.Errorf("got %+v, want the GitHub token once, on line 2, and the Slack token", leaks)
	}
}

func TestOtherPrivateKeyFormats(t *testing.T) {
	_, data := pemKey("RSA "+"PRIVATE KEY", 900)
	lines := []string{data[:64], data[64:128], data[128:192], data[192:256]}
	ssh2 := "---- BEGIN SSH2 ENCRYPTED " + "PRIVATE KEY ----\nComment: \"rsa-key-20261104\"\n" + strings.Join(lines, "\n") + "\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n"
	putty := "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: rsa-key-20261104\nPublic-Lines: 1\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\nPrivate-Lines: 4\n" +
		strings.Join(lines, "\n") + "\nPrivate-MAC: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
	shell := "KEY=\"-----BEGIN " + "RSA PRIVATE KEY-----\\\n" + strings.Join(lines, "\\\n") + "\\\n-----END RSA PRIVATE KEY-----\"\n"
	for name, text := range map[string]string{"ssh2": ssh2, "putty": putty, "shell continuation": shell} {
		leaks, err := ScanReader("k", strings.NewReader(text), Options{})
		if err != nil || len(leaks) != 1 || leaks[0].RuleID != "private-key" || leaks[0].Line != 1 {
			t.Errorf("%s: got %+v, %v; want the key on line 1", name, leaks, err)
		}
		if len(leaks) == 1 && strings.Contains(leaks[0].Redacted, data[:8]) {
			t.Errorf("%s: Redacted shows key data: %q", name, leaks[0].Redacted)
		}
	}
}

func TestSkippedAndLinkedFiles(t *testing.T) {
	dir := t.TempDir()
	token := "ghp_" + fake(alnum, 36, 901)
	big := strings.Repeat("x", 2048) + "\ntoken: " + token + "\n"
	if err := os.WriteFile(filepath.Join(dir, "bundle.js"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("token: "+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symbolic links are not available")
	}
	var skipped []string
	opts := Options{MaxFileSize: 1024, Skipped: func(path string, size int64) { skipped = append(skipped, path) }}
	leaks, err := ScanDir(context.Background(), dir, opts)
	if err != nil || len(leaks) != 0 {
		t.Errorf("got %+v, %v; want nothing scanned", leaks, err)
	}
	if len(skipped) != 1 || skipped[0] != "bundle.js" {
		t.Errorf("skipped = %v, want the large file reported", skipped)
	}
	// A file swapped for a link after the directory was listed is not
	// followed.
	if got, err := scanFile(link, "link.txt", opts.withDefaults()); err != nil || len(got) != 0 {
		t.Errorf("scanFile followed a link: %+v, %v", got, err)
	}
}
