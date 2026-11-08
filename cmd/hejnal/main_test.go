package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

const kevSample = "../../testdata/kev_sample.json"

type harness struct {
	t        *testing.T
	dir      string
	scope    string
	state    string
	mu       sync.Mutex
	messages []string
	failHook bool // the webhook answers 503 once
	hook     *httptest.Server
}

// newHarness starts a WordPress-on-PHP site and a chat webhook, and writes a
// scope that authorises checking the site on 127.0.0.1.
func newHarness(t *testing.T) *harness {
	h := &harness{t: t, dir: t.TempDir()}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
		io.WriteString(w, `<html><head><title>Sklep</title><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	}))
	t.Cleanup(site.Close)
	h.hook = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]string
		json.NewDecoder(r.Body).Decode(&msg)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.failHook {
			h.failHook = false
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		h.messages = append(h.messages, msg["text"])
	}))
	t.Cleanup(h.hook.Close)

	u, _ := url.Parse(site.URL)
	scope := `{
  "organization": "Sklep Sp. z o.o.",
  "authorization": {"confirmedBy": "Anna Nowak, IT", "date": "2026-11-01", "statement": "We own this system."},
  "hosts": ["127.0.0.1"],
  "ports": [` + u.Port() + `]
}`
	h.scope = filepath.Join(h.dir, "scope.json")
	h.state = filepath.Join(h.dir, "state")
	if err := os.WriteFile(h.scope, []byte(scope), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.now = func() time.Time { return testNow }
	code = a.run(context.Background(), args)
	return code, out.String(), errOut.String()
}

func (h *harness) runArgs(extra ...string) []string {
	return append([]string{"run", "-scope", h.scope, "-state", h.state, "-kev-file", kevSample,
		"-no-epss", "-no-nvd", "-no-ct", "-timeout", "3s", "-webhook", h.hook.URL + "/hook"}, extra...)
}

func TestRunEndToEnd(t *testing.T) {
	h := newHarness(t)

	code, out, errOut := h.run(h.runArgs("-fail-on", "high")...)
	if code != exitFindings {
		t.Fatalf("first run exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
	}
	if !strings.Contains(errOut, "Authorised by Anna Nowak, IT on 2026-11-01") {
		t.Errorf("authorisation banner missing:\n%s", errOut)
	}
	for _, want := range []string{"First check", "[critical] WordPress on 127.0.0.1", "CVE-2026-119977", "Fix list written to"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout is missing %q:\n%s", want, out)
		}
	}
	fix, err := os.ReadFile(filepath.Join(h.state, "fixlist.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Fix now (critical)", "CVE-2026-109618", "version `6.8.1`"} {
		if !strings.Contains(string(fix), want) {
			t.Errorf("fix list is missing %q", want)
		}
	}
	if len(h.messages) != 1 || !strings.Contains(h.messages[0], "First check") {
		t.Fatalf("webhook messages = %q", h.messages)
	}

	// Nothing changed: no new findings, no message, exit 0.
	code, out, errOut = h.run(h.runArgs("-fail-on", "high")...)
	if code != exitOK {
		t.Fatalf("second run exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "New: 0 · Resolved: 0") {
		t.Errorf("second run summary:\n%s", out)
	}
	if len(h.messages) != 1 {
		t.Errorf("webhook called again without new findings: %d messages", len(h.messages))
	}

	// Reports from the saved state, with flags before or after the name.
	code, out, _ = h.run("report", "nis2", "-state", h.state, "-lang", "pl")
	if code != exitOK || !strings.Contains(out, "NIS2: wczesne ostrzeżenie") || !strings.Contains(out, "CVE-2026-119977") {
		t.Errorf("nis2 report (exit %d):\n%s", code, out)
	}
	code, out, _ = h.run("report", "-lang", "pl", "-state", h.state, "fixlist")
	if code != exitOK || !strings.Contains(out, "Napraw teraz (krytyczne)") {
		t.Errorf("fixlist report (exit %d):\n%s", code, out)
	}
	code, out, _ = h.run("report", "monthly", "-state", h.state, "-month", "2026-11")
	if code != exitOK || !strings.Contains(out, "Hejnal monthly report, November 2026") || !strings.Contains(out, "Runs: 1") { // both runs share the fixed test clock
		t.Errorf("monthly report (exit %d):\n%s", code, out)
	}
	if code, _, _ = h.run("report", "monthly", "-state", h.state, "-month", "Nov"); code != exitError {
		t.Errorf("a malformed -month was accepted")
	}
	outFile := filepath.Join(h.dir, "fix.md")
	if code, _, _ = h.run("report", "fixlist", "-state", h.state, "-o", outFile); code != exitOK {
		t.Errorf("report -o exit = %d", code)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error(err)
	}

	// discover and match separately give the same findings.
	if code, out, errOut = h.run("discover", "-scope", h.scope, "-state", h.state, "-no-ct"); code != exitOK {
		t.Fatalf("discover exit = %d\n%s\n%s", code, out, errOut)
	}
	if code, out, errOut = h.run("match", "-state", h.state, "-kev-file", kevSample, "-no-epss", "-no-nvd"); code != exitOK {
		t.Fatalf("match exit = %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "New: 0 · Resolved: 0") {
		t.Errorf("match summary:\n%s", out)
	}
}

func TestFailedWebhookReportsAgain(t *testing.T) {
	h := newHarness(t)
	h.failHook = true
	code, _, errOut := h.run(h.runArgs("-fail-on", "high")...)
	if code != exitError || !strings.Contains(errOut, "503") {
		t.Fatalf("exit %d, stderr:\n%s", code, errOut)
	}
	// The next run must deliver the findings the failed run could not.
	code, _, errOut = h.run(h.runArgs("-fail-on", "high")...)
	if code != exitFindings {
		t.Fatalf("second run exit = %d, want %d\n%s", code, exitFindings, errOut)
	}
	if len(h.messages) != 1 || !strings.Contains(h.messages[0], "CVE-2026-119977") {
		t.Errorf("webhook messages = %q", h.messages)
	}
}

func TestRunRefusesUnauthorisedScope(t *testing.T) {
	h := newHarness(t)
	os.WriteFile(h.scope, []byte(`{"organization": "X", "hosts": ["127.0.0.1"]}`), 0o600)
	code, _, errOut := h.run(h.runArgs()...)
	if code != exitError || !strings.Contains(errOut, "confirmedBy is required") {
		t.Errorf("exit %d, stderr:\n%s", code, errOut)
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		h.runArgs("-lang", "de"),
		h.runArgs("-fail-on", "urgent"),
		h.runArgs("-webhook", "http://hooks.example.com/x"),
		{"run", "-no-such-flag"},
		{"run", "extra-argument"},
		{"report", "summary", "-state", h.state},
		{"bogus"},
		{},
	} {
		if code, _, _ := h.run(args...); code != exitError {
			t.Errorf("%v: exit %d, want %d", args, code, exitError)
		}
	}
	if code, _, _ := h.run("run", "-h"); code != exitOK {
		t.Errorf("-h exit = %d", code)
	}
}

func TestInit(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "new-scope.json")
	code, out, _ := h.run("init", "-scope", path)
	if code != exitOK || !strings.Contains(out, "hejnal run -scope") {
		t.Fatalf("init exit %d:\n%s", code, out)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("scope mode = %v", fi.Mode().Perm())
	}
	if code, _, errOut := h.run("init", "-scope", path); code != exitError || !strings.Contains(errOut, "already exists") {
		t.Errorf("second init exit %d: %s", code, errOut)
	}
	// The example must be a valid scope (it fails only on the network).
	a := newApp(io.Discard, io.Discard)
	a.now = func() time.Time { return testNow }
	if _, err := a.loadScope(path); err != nil {
		t.Errorf("example scope does not load: %v", err)
	}
}

func TestVersionAndRules(t *testing.T) {
	h := newHarness(t)
	if code, out, _ := h.run("version"); code != exitOK || !strings.HasPrefix(out, "hejnal ") {
		t.Errorf("version: %d %q", code, out)
	}
	code, out, _ := h.run("rules")
	if code != exitOK || !strings.Contains(out, "fortinet-fortigate") {
		t.Errorf("rules: %d\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "exim":
			if !strings.Contains(line, "greeting") || strings.Contains(line, "web page") {
				t.Errorf("exim is recognised by its greeting only: %q", line)
			}
		case "fortinet-fortigate":
			if !strings.Contains(line, "web page") || strings.Contains(line, "greeting") {
				t.Errorf("FortiGate is recognised by its web page only: %q", line)
			}
		case "moveit":
			if !strings.Contains(line, "web page, greeting") {
				t.Errorf("MOVEit is recognised by both: %q", line)
			}
		}
	}
}

func TestMatchBeforeDiscover(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("match", "-state", h.state, "-kev-file", kevSample)
	if code != exitError || !strings.Contains(errOut, "no inventory yet") {
		t.Errorf("exit %d: %s", code, errOut)
	}
	code, _, errOut = h.run("report", "fixlist", "-state", h.state)
	if code != exitError || !strings.Contains(errOut, "no findings yet") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestFeedsDownloadsBothLists(t *testing.T) {
	kevData, err := os.ReadFile(kevSample)
	if err != nil {
		t.Fatal(err)
	}
	dump, err := os.ReadFile(filepath.Join(filepath.Dir(kevSample), "euvd_kev_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			w.Write(kevData)
		case "/dump":
			w.Write(dump)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.now = func() time.Time { return testNow }
	a.kevURL, a.euvdURL, a.euvdRecordURL = srv.URL+"/kev.json", srv.URL+"/dump", srv.URL+"/record"
	dir := t.TempDir()
	if code := a.run(context.Background(), []string{"feeds", "-state", dir}); code != exitOK {
		t.Fatalf("feeds exit %d: %s", code, errOut.String())
	}
	// 21 flaws from CISA, and 10 ENISA lists, 7 of them not in this
	// sample of CISA's catalog.
	for _, want := range []string{"CISA KEV catalog 2026.11.03: 21 known exploited flaws.",
		"ENISA EUVD list of " + time.Now().UTC().Add(-7*time.Hour).Format("2006-01-02") + ": 10 known exploited flaws, 7 of them not in CISA's catalog."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("feeds output is missing %q:\n%s", want, out.String())
		}
	}
	for _, f := range []string{"kev.json", "euvd-kev.json"} {
		if _, err := os.Stat(filepath.Join(dir, "cache", f)); err != nil {
			t.Errorf("%s not saved: %v", f, err)
		}
	}
}
