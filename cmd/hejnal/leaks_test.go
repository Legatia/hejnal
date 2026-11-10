package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeToken is built at run time so that no complete token appears in the
// source code.
var fakeToken = "ghp_" + strings.Repeat("a1B2", 9)

func TestLeaksScan(t *testing.T) {
	h := newHarness(t)
	repo := filepath.Join(h.dir, "website")
	if err := os.MkdirAll(filepath.Join(repo, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "app", "settings.py"), []byte("GITHUB_TOKEN = \""+fakeToken+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := h.run("leaks", "scan", "-save", "-state", h.state, repo)
	if code != exitFindings {
		t.Fatalf("code %d, want %d\n%s%s", code, exitFindings, out, errOut)
	}
	for _, want := range []string{"GitHub token", "website/app/settings.py:1", "ghp_a1… (40 chars)", "1 secret found (critical 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	saved, err := os.ReadFile(filepath.Join(h.state, "leaks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out+errOut+string(saved), fakeToken) {
		t.Error("the full secret was printed or stored")
	}
	// Saved scans use a private key, so fingerprints stay the same across
	// scans but cannot be checked against guesses without it.
	if st, err := os.Stat(filepath.Join(h.state, "leaks.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("fingerprint key: %v", err)
	}
	if code, _, _ := h.run("leaks", "scan", "-save", "-state", h.state, repo); code != exitFindings {
		t.Fatalf("second scan: code %d", code)
	}
	again, _ := os.ReadFile(filepath.Join(h.state, "leaks.json"))
	fp := func(data []byte) string {
		var scan struct {
			Leaks []struct{ Fingerprint string } `json:"leaks"`
		}
		json.Unmarshal(data, &scan)
		if len(scan.Leaks) != 1 {
			return ""
		}
		return scan.Leaks[0].Fingerprint
	}
	if fp(saved) == "" || fp(saved) != fp(again) {
		t.Errorf("fingerprints differ between saved scans: %q and %q", fp(saved), fp(again))
	}

	// The next run's fix list includes the saved secret.
	if code, _, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run: code %d\n%s", code, errOut)
	}
	fix, err := os.ReadFile(filepath.Join(h.state, "fixlist.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fix), "Secret in source code: GitHub token") || strings.Contains(string(fix), fakeToken) {
		t.Errorf("fix list:\n%s", fix)
	}

	// -fail-on none exits 0, and -json prints the leaks, flags after the
	// directory included.
	code, out, errOut = h.run("leaks", "scan", repo, "-json", "-fail-on", "none")
	if code != exitOK {
		t.Fatalf("code %d\n%s", code, errOut)
	}
	var leaked []map[string]any
	if err := json.Unmarshal([]byte(out), &leaked); err != nil || len(leaked) != 1 || leaked[0]["ruleId"] != "github-token" {
		t.Errorf("JSON output %q: %v", out, err)
	}

	// A clean directory passes.
	clean := filepath.Join(h.dir, "clean")
	os.MkdirAll(clean, 0o700)
	if code, out, _ := h.run("leaks", "scan", clean); code != exitOK || !strings.Contains(out, "No secrets found.") {
		t.Errorf("clean directory: code %d, %q", code, out)
	}
	if code, _, _ := h.run("leaks", "scan"); code != exitError {
		t.Errorf("no directory: code %d", code)
	}
}

// TestLeaksScanExclude checks that -exclude leaves a directory out and that
// the default skip list still applies with it.
func TestLeaksScanExclude(t *testing.T) {
	h := newHarness(t)
	repo := filepath.Join(h.dir, "website")
	secret := []byte("GITHUB_TOKEN = \"" + fakeToken + "\"\n")
	for _, file := range []string{"parser/testdata/token.py", "node_modules/pkg/token.py"} {
		full := filepath.Join(repo, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, secret, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	code, out, errOut := h.run("leaks", "scan", repo)
	if code != exitFindings || !strings.Contains(out, "website/parser/testdata/token.py:1") || strings.Contains(out, "node_modules") {
		t.Fatalf("without -exclude: code %d\n%s%s", code, out, errOut)
	}
	for _, dir := range []string{"testdata", "parser/testdata"} {
		code, out, errOut = h.run("leaks", "scan", "-exclude", dir, repo)
		if code != exitOK || !strings.Contains(out, "No secrets found.") {
			t.Errorf("-exclude %s: code %d\n%s%s", dir, code, out, errOut)
		}
	}
	// A path counts from the scanned directory, so this one names nothing.
	if code, _, _ := h.run("leaks", "scan", "-exclude", "website/parser", repo); code != exitFindings {
		t.Errorf("-exclude website/parser: code %d, want %d", code, exitFindings)
	}
	if code, _, errOut := h.run("leaks", "scan", "-exclude", "../other", repo); code != exitError || !strings.Contains(errOut, "-exclude") {
		t.Errorf("-exclude ../other: code %d, %q", code, errOut)
	}
}

func TestLeaksBreaches(t *testing.T) {
	h := newHarness(t)
	hibp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("hibp-api-key") != "test-key" || r.Header.Get("User-Agent") == "" {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/breacheddomain/sklep.test":
			io.WriteString(w, `{"anna":["Adobe"],"jan":["Adobe","Spamlist"]}`)
		case "/breach/Adobe":
			io.WriteString(w, `{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","AddedDate":"2013-12-04T00:00:00Z","PwnCount":152445165,"DataClasses":["Email addresses","Password hints","Passwords","Usernames"],"IsVerified":true,"IsSensitive":false,"IsSpamList":false}`)
		case "/breach/Spamlist":
			io.WriteString(w, `{"Name":"Spamlist","Title":"Spam list","BreachDate":"2020-01-01","AddedDate":"2020-01-02T00:00:00Z","PwnCount":1000,"DataClasses":["Email addresses"],"IsVerified":false,"IsSensitive":false,"IsSpamList":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer hibp.Close()
	scopePath := filepath.Join(h.dir, "domains.json")
	scope := `{"organization": "Sklep", "authorization": {"confirmedBy": "Anna Nowak, IT", "date": "2026-11-01", "statement": "We own this domain."}, "domains": ["sklep.test"]}`
	if err := os.WriteFile(scopePath, []byte(scope), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut)
		a.now = func() time.Time { return testNow }
		a.hibpURL = hibp.URL
		code := a.run(context.Background(), args)
		return code, out.String(), errOut.String()
	}

	t.Setenv("HEJNAL_HIBP_API_KEY", "")
	if code, _, errOut := run("leaks", "breaches", "-scope", scopePath, "-state", h.state); code != exitError || !strings.Contains(errOut, "HEJNAL_HIBP_API_KEY") {
		t.Errorf("without a key: code %d, %q", code, errOut)
	}

	t.Setenv("HEJNAL_HIBP_API_KEY", "test-key")
	code, out, errOut := run("leaks", "breaches", "-scope", scopePath, "-state", h.state)
	if code != exitOK {
		t.Fatalf("code %d\n%s", code, errOut)
	}
	for _, want := range []string{"sklep.test: 2 accounts in 2 breaches.", "Adobe (2013-10-04): 2 accounts, passwords exposed", "Spam list (2020-01-01): 1 account"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	saved, err := os.ReadFile(filepath.Join(h.state, "breaches.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out+string(saved), "anna") {
		t.Errorf("account names were printed or stored without -accounts:\n%s\n%s", out, saved)
	}

	code, out, _ = run("leaks", "breaches", "-accounts", "-scope", scopePath, "-state", h.state)
	if code != exitOK || !strings.Contains(out, "anna@sklep.test, jan@sklep.test") {
		t.Errorf("-accounts: code %d\n%s", code, out)
	}
	saved, _ = os.ReadFile(filepath.Join(h.state, "breaches.json"))
	if strings.Contains(string(saved), "anna") {
		t.Error("-accounts stored account names")
	}
}
