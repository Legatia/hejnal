package main

import (
	"bytes"
	"cmp"
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

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/scope"
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
	failHook bool   // the webhook answers 503 once
	php      string // the PHP version the site shows; 8.3.12 when empty
	siteURL  string
	hook     *httptest.Server
}

// setPHP changes the PHP version the site shows.
func (h *harness) setPHP(v string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.php = v
}

// newHarness starts a WordPress-on-PHP site and a chat webhook, and writes a
// scope that authorises checking the site on 127.0.0.1.
func newHarness(t *testing.T) *harness {
	h := &harness{t: t, dir: t.TempDir()}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		php := cmp.Or(h.php, "8.3.12")
		h.mu.Unlock()
		w.Header().Set("X-Powered-By", "PHP/"+php)
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

	h.siteURL = site.URL
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
	a.githubPause = 0
	a.livePause = 10 * time.Millisecond
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
	overview := filepath.Join(h.dir, "overview.html")
	if code, _, errOut = h.run("report", "overview", "-state", h.state, "-by", "Legatia Solutions", "-o", overview); code != exitOK {
		t.Fatalf("overview exit = %d\n%s", code, errOut)
	}
	page, err := os.ReadFile(overview)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<!doctype html>", "Prepared by Legatia Solutions", "Needs action now", "WordPress on 127.0.0.1",
		"<td>Websites and CMS</td>", "<span>Exploited flaws checked</span>"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("overview is missing %q", want)
		}
	}
	code, out, errOut = h.run("report", "evidence", "-state", h.state, "-lang", "pl")
	if code != exitOK || !strings.Contains(out, "Dowód monitorowania podatności") || !strings.Contains(out, "WordPress na 127.0.0.1") {
		t.Errorf("evidence report (exit %d):\n%s\n%s", code, out, errOut)
	}
	if code, _, _ = h.run("report", "evidence", "-state", h.state, "-since", "last week"); code != exitError {
		t.Errorf("a malformed -since was accepted")
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

func TestRunReportsSystemChanges(t *testing.T) {
	h := newHarness(t)
	if code, out, errOut := h.run(h.runArgs()...); code != exitOK || strings.Contains(out, "Systems ·") {
		t.Fatalf("first run exit %d: the first run only records what answers\n%s\n%s", code, out, errOut)
	}
	port := strings.TrimPrefix(h.siteURL, "http://127.0.0.1:")
	updated := "• Updated: PHP 8.3.12 → 8.3.14 on 127.0.0.1 (" + port + ")"

	// PHP is upgraded; the message about it fails to go out.
	h.setPHP("8.3.14")
	h.failHook = true
	code, out, errOut := h.run(h.runArgs()...)
	if code != exitError || !strings.Contains(out, "Systems · new: 0 · gone: 0 · updated: 1") || !strings.Contains(out, updated) {
		t.Fatalf("second run exit %d:\n%s\n%s", code, out, errOut)
	}
	// The next run delivers it, though nothing else is new.
	if code, _, errOut = h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("third run exit %d:\n%s", code, errOut)
	}
	if len(h.messages) != 2 || !strings.Contains(h.messages[1], updated) {
		t.Fatalf("webhook messages = %q", h.messages)
	}
	// Once told, it is not news any more.
	if code, out, _ = h.run(h.runArgs()...); code != exitOK || strings.Contains(out, "Systems ·") || len(h.messages) != 2 {
		t.Errorf("fourth run exit %d, %d messages:\n%s", code, len(h.messages), out)
	}
	recs, err := os.ReadFile(filepath.Join(h.state, "systems.json"))
	if err != nil || !strings.Contains(string(recs), `"version": "8.3.14"`) {
		t.Errorf("systems.json: %v\n%s", err, recs)
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
	// The example is a valid scope file, but Hejnal does not run it: its
	// entries are not the user's systems.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Parse(data, testNow); err != nil {
		t.Errorf("example scope does not parse: %v", err)
	}
	code, _, errOut := h.run("run", "-scope", path, "-offline")
	if code != exitError {
		t.Errorf("run with the example scope: exit %d", code)
	}
	for _, want := range []string{"still has entries from the example", "example.com", "Jan Kowalski", "203.0.113.0/29"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("refusal does not name %q:\n%s", want, errOut)
		}
	}
}

func TestInitReady(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "ready.json")
	code, out, errOut := h.run("init", "-scope", path, "-domain", "sklep.test, biuro.test", "-by", "Anna Nowak, owner")
	if code != exitOK {
		t.Fatalf("init exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "sklep.test, biuro.test") || !strings.Contains(out, "Anna Nowak, owner") {
		t.Errorf("init does not say what it recorded:\n%s", out)
	}
	a := newApp(io.Discard, io.Discard)
	a.now = func() time.Time { return testNow }
	s, err := a.loadScope(path)
	if err != nil {
		t.Fatalf("ready scope does not load: %v", err)
	}
	if s.Organization != "sklep.test" || len(s.Domains) != 2 || len(s.Hosts)+len(s.CIDRs)+len(s.Exclude) != 0 {
		t.Errorf("scope = %+v", s)
	}
	if s.Authorization.ConfirmedBy != "Anna Nowak, owner" || s.Authorization.Date != testNow.Format("2006-01-02") {
		t.Errorf("authorization = %+v", s.Authorization)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-domain", "sklep.test"}, "needs both -domain and -by"},
		{[]string{"-by", "Anna Nowak"}, "needs both -domain and -by"},
		{[]string{"-org", "Sklep"}, "needs both -domain and -by"},
		{[]string{"-domain", "example.com", "-by", "Anna Nowak"}, "is an example"},
		{[]string{"-domain", "not a domain", "-by", "Anna Nowak"}, ""},
	} {
		p := filepath.Join(h.dir, "bad.json")
		code, _, errOut := h.run(append([]string{"init", "-scope", p}, tc.args...)...)
		if code != exitError || !strings.Contains(errOut, tc.want) {
			t.Errorf("init %v: exit %d: %s", tc.args, code, errOut)
		}
		if _, err := os.Stat(p); err == nil {
			t.Errorf("init %v wrote a file", tc.args)
			os.Remove(p)
		}
	}

	path = filepath.Join(h.dir, "org.json")
	if code, _, errOut := h.run("init", "-scope", path, "-domain", "sklep.test", "-by", "Anna Nowak", "-org", "Sklep Sp. z o.o."); code != exitOK {
		t.Fatalf("init -org exit %d: %s", code, errOut)
	}
	if s, err := a.loadScope(path); err != nil || s.Organization != "Sklep Sp. z o.o." {
		t.Errorf("-org: %v %+v", err, s)
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
	dates, err := os.ReadFile(filepath.Join(filepath.Dir(kevSample), "eol_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			w.Write(kevData)
		case "/dump":
			w.Write(dump)
		case "/eol":
			w.Write(dates)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.now = func() time.Time { return testNow }
	a.kevURL, a.euvdURL, a.euvdRecordURL, a.eolURL = srv.URL+"/kev.json", srv.URL+"/dump", srv.URL+"/record", srv.URL+"/eol"
	dir := t.TempDir()
	if code := a.run(context.Background(), []string{"feeds", "-state", dir}); code != exitOK {
		t.Fatalf("feeds exit %d: %s", code, errOut.String())
	}
	// 21 flaws from CISA, and 10 ENISA lists, 7 of them not in this
	// sample of CISA's catalog.
	for _, want := range []string{"CISA KEV catalog 2026.11.03: 21 known exploited flaws.",
		"ENISA EUVD list of " + time.Now().UTC().Add(-7*time.Hour).Format("2006-01-02") + ": 10 known exploited flaws, 7 of them not in CISA's catalog.",
		"endoflife.date end-of-support dates of 2026-11-14: 7 products."} {
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

func TestChecksTip(t *testing.T) {
	kev := func(tech, name, version string) match.Finding {
		return match.Finding{Kind: match.KindKEV, TechID: tech, Technology: name, Version: version, Confidence: match.ConfidenceProduct}
	}
	// Next.js and WordPress can show a version to -checks; FortiGate cannot.
	fs := []match.Finding{
		kev("nextjs-app-router", "Next.js", ""), kev("nextjs-app-router", "Next.js", ""),
		kev("wordpress", "WordPress", ""), kev("fortinet-fortigate", "FortiGate", ""),
	}
	tip := checksTip(fs)
	if !strings.HasPrefix(tip, "Tip: Next.js, WordPress did not show its version") || !strings.Contains(tip, "-checks") || strings.Contains(tip, "FortiGate") {
		t.Errorf("tip = %q", tip)
	}
	// Nothing to say when the version is known, the flaw is ruled out or
	// accepted, or the finding is not about a product.
	ruledOut := kev("wordpress", "WordPress", "")
	ruledOut.Confidence = match.ConfidenceRuledOut
	accepted := kev("wordpress", "WordPress", "")
	accepted.Accepted = &match.Acceptance{}
	quiet := []match.Finding{kev("wordpress", "WordPress", "6.8.1"), ruledOut, accepted, {Kind: match.KindExposedFile, TechID: "wordpress"}}
	if tip := checksTip(quiet); tip != "" {
		t.Errorf("tip = %q, want none", tip)
	}
}

func TestSystemsCommand(t *testing.T) {
	h := newHarness(t)
	// Before the first run there is nothing on record.
	if code, out, errOut := h.run("systems", "-state", h.state); code != exitOK || !strings.Contains(out, "No systems on record yet") {
		t.Fatalf("empty record exit %d:\n%s\n%s", code, out, errOut)
	}
	if code, _, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("first run exit %d:\n%s", code, errOut)
	}
	h.setPHP("8.3.14")
	if code, _, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("second run exit %d:\n%s", code, errOut)
	}
	port := strings.TrimPrefix(h.siteURL, "http://127.0.0.1:")

	code, out, errOut := h.run("systems", "-state", h.state)
	if code != exitOK || !strings.Contains(out, "# Systems: Sklep Sp. z o.o.") || !strings.Contains(out, "**Systems: 1 · answering: 1 · gone: 0**") ||
		!strings.Contains(out, "| 127.0.0.1 | "+port+" | ") || !strings.Contains(out, "PHP 8.3.14") {
		t.Fatalf("list exit %d:\n%s\n%s", code, out, errOut)
	}
	// The host may come before or after the flags.
	for _, args := range [][]string{
		{"systems", "127.0.0.1", "-state", h.state},
		{"system", "-state", h.state, "127.0.0.1"},
	} {
		code, out, errOut = h.run(args...)
		for _, want := range []string{
			"# System history: 127.0.0.1",
			"- **Status:** answering",
			"· First answer · port " + port,
			"· PHP 8.3.12 → 8.3.14 · port " + port,
		} {
			if code != exitOK || !strings.Contains(out, want) {
				t.Fatalf("%v exit %d, missing %q:\n%s\n%s", args, code, want, out, errOut)
			}
		}
	}
	if code, out, _ = h.run("systems", "127.0.0.1", "-state", h.state, "-lang", "pl"); code != exitOK || !strings.Contains(out, "# Historia systemu: 127.0.0.1") {
		t.Errorf("polish exit %d:\n%s", code, out)
	}
	code, out, _ = h.run("systems", "127.0.0.1", "-state", h.state, "-format", "json")
	var sys report.System
	if err := json.Unmarshal([]byte(out), &sys); code != exitOK || err != nil || sys.Host != "127.0.0.1" || len(sys.Events) < 2 {
		t.Errorf("json exit %d: %v\n%s", code, err, out)
	}
	code, out, _ = h.run("systems", "-state", h.state, "-format", "json")
	var list struct {
		Systems []report.System `json:"systems"`
	}
	if err := json.Unmarshal([]byte(out), &list); code != exitOK || err != nil || len(list.Systems) != 1 {
		t.Errorf("json list exit %d: %v\n%s", code, err, out)
	}
	file := filepath.Join(h.dir, "history.md")
	if code, out, _ = h.run("systems", "127.0.0.1", "-state", h.state, "-o", file); code != exitOK || out != "" {
		t.Errorf("-o exit %d:\n%s", code, out)
	}
	if data, err := os.ReadFile(file); err != nil || !strings.Contains(string(data), "# System history: 127.0.0.1") {
		t.Errorf("history file: %v\n%s", err, data)
	}
	if code, _, errOut = h.run("systems", "unknown.example.com", "-state", h.state); code != exitError || !strings.Contains(errOut, `no system "unknown.example.com" on record`) {
		t.Errorf("unknown host exit %d:\n%s", code, errOut)
	}
	if code, _, errOut = h.run("systems", "127.0.0.1", "extra", "-state", h.state); code != exitError || !strings.Contains(errOut, "unexpected argument") {
		t.Errorf("two hosts exit %d:\n%s", code, errOut)
	}
	if code, _, _ = h.run("systems", "-state", h.state, "-format", "xml"); code != exitError {
		t.Errorf("-format xml exit %d", code)
	}
	// The evidence lists the system.
	if code, out, errOut = h.run("report", "evidence", "-state", h.state); code != exitOK || !strings.Contains(out, "Systems on record") || !strings.Contains(out, `<td class="item-title">127.0.0.1</td>`) {
		t.Errorf("evidence exit %d:\n%s", code, errOut)
	}
}
