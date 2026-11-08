package fingerprint

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// Scanned systems are not trusted: whatever a service answers, matching must
// not crash, and what it reports must stay small and printable.
func FuzzIdentify(f *testing.F) {
	eng, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	f.Add("Server: Apache/2.4.49 (Unix)\nX-Powered-By: PHP/8.3.12", "/", `<html><head><title>Test</title><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	f.Add("Set-Cookie: JSESSIONID=1; Path=/", "/login", "<title>Jenkins</title>")
	f.Add("Server: \x00\xff", "/\x00", "<meta name=generator content='a'><title><title>")
	f.Fuzz(func(t *testing.T, headers, path, body string) {
		h := http.Header{}
		for _, line := range strings.Split(headers, "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok {
				h.Add(k, strings.TrimSpace(v))
			}
		}
		for _, tech := range eng.Identify(NewResponse(h, path, body)) {
			checkTech(t, tech.ID, tech.Version)
		}
	})
}

func FuzzBanner(f *testing.F) {
	eng, err := Default()
	if err != nil {
		f.Fatal(err)
	}
	f.Add("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
	f.Add("220 ProFTPD 1.3.8 Server (Debian)")
	f.Add("220 mail ESMTP Exim 4.97 \x00\r\n")
	f.Fuzz(func(t *testing.T, banner string) {
		for _, tech := range eng.Identify(NewBanner(banner)) {
			checkTech(t, tech.ID, tech.Version)
		}
	})
}

func checkTech(t *testing.T, id, version string) {
	t.Helper()
	if id == "" {
		t.Fatal("a technology without an ID")
	}
	if len(version) > 100 || !utf8.ValidString(version) {
		t.Fatalf("version %q is too long or not UTF-8", version)
	}
	for _, r := range version {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("version %q has control characters", version)
		}
	}
}
