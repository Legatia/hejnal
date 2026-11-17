package main

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// liveArgs are the flags of a live check that reads its feeds from files.
func (h *harness) liveArgs(extra ...string) []string {
	return append([]string{"live", "-scope", h.scope, "-state", h.state, "-kev-file", kevSample,
		"-no-epss", "-no-nvd", "-timeout", "3s"}, extra...)
}

// writeScope replaces the harness's scope file.
func (h *harness) writeScope(body string) {
	h.t.Helper()
	scope := `{
  "organization": "Sklep Sp. z o.o.",
  "authorization": {"confirmedBy": "Anna Nowak, IT", "date": "2026-11-01", "statement": "We own this system."},
  ` + body + `
}`
	if err := os.WriteFile(h.scope, []byte(scope), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// stateFiles reads every file in the state directory.
func (h *harness) stateFiles() map[string]string {
	h.t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(h.state, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		files[p] = string(data)
		return err
	})
	if err != nil && !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
	return files
}

func portString(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func TestLiveChecksOneSystem(t *testing.T) {
	h := newHarness(t)

	code, out, errOut := h.run(h.liveArgs(h.siteURL + "/health?token=secret")...)
	if code != exitFindings {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
	}
	for _, want := range []string{"Checked " + h.siteURL + "\n", `Answer: 200 "Sklep"`, "WordPress 6.8.1", "PHP 8.3.12", "CRITICAL", "CVE-2026-119977", "at " + h.siteURL} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout is missing %q:\n%s", want, out)
		}
	}
	for _, want := range []string{"Authorised by Anna Nowak, IT on 2026-11-01", "Checking only " + h.siteURL + ".", "not at /health"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr is missing %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(out+errOut, "secret") {
		t.Errorf("the address's query string is repeated:\n%s\n%s", out, errOut)
	}
	if files := h.stateFiles(); len(files) != 0 {
		t.Errorf("a live check saved %v", files)
	}

	if code, out, errOut = h.run(h.liveArgs("-fail-on", "none", h.siteURL)...); code != exitOK {
		t.Fatalf("exit with -fail-on none = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
}

func TestLiveLeavesTheRecordAlone(t *testing.T) {
	h := newHarness(t)
	if code, out, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	before := h.stateFiles()
	if len(before) == 0 {
		t.Fatal("the run saved nothing")
	}
	h.setPHP("8.4.1")
	if code, out, errOut := h.run(h.liveArgs(h.siteURL)...); code != exitFindings {
		t.Fatalf("live exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	} else if !strings.Contains(out, "PHP 8.4.1") {
		t.Errorf("the live check did not look again:\n%s", out)
	}
	after := h.stateFiles()
	for name, data := range after {
		if old, ok := before[name]; !ok {
			t.Errorf("the live check wrote %s", name)
		} else if old != data {
			t.Errorf("the live check changed %s", name)
		}
	}
}

func TestLiveHonoursAcceptedItems(t *testing.T) {
	h := newHarness(t)
	if code, out, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	// The fix list names each item's ID, which "accept" takes.
	code, out, errOut := h.run("report", "fixlist", "-state", h.state)
	if code != exitOK {
		t.Fatalf("report exit = %d\n%s\n%s", code, out, errOut)
	}
	var ids []string
	for _, f := range strings.Fields(out) {
		if id := strings.Trim(f, "`"); len(id) == 8 && strings.Trim(id, "0123456789abcdef") == "" && strings.HasPrefix(f, "`") {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		t.Fatalf("no item IDs in the fix list:\n%s", out)
	}
	for _, id := range ids {
		if code, out, errOut := h.run("accept", "-item", id, "-reason", "checked by hand", "-by", "Anna", "-state", h.state); code != exitOK {
			t.Fatalf("accept %s exit = %d\n%s\n%s", id, code, out, errOut)
		}
	}
	code, out, errOut = h.run(h.liveArgs(h.siteURL)...)
	if code != exitOK {
		t.Fatalf("live exit = %d, want %d once every item is accepted\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
	if !strings.Contains(out, "Nothing found.") || !strings.Contains(out, "Not listed:") {
		t.Errorf("stdout does not say the items are accepted:\n%s", out)
	}
}

func TestLiveRefusesWhatTheScopeDoesNotAllow(t *testing.T) {
	h := newHarness(t)
	var hits atomic.Int32
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer site.Close()
	port := portString(t, site.URL)
	h.writeScope(`"domains": ["example.test"], "hosts": ["127.0.0.1"], "ports": [` + portString(t, h.siteURL) + `]`)

	for _, tc := range []struct{ arg, want string }{
		{"http://localhost:" + port, "localhost is not in the scope file"},
		{site.URL, "port " + port + " is not among the ports in the scope file"},
		{"https://app.example.test:8443", "a name under a domain is checked on ports 80, 443 only"},
		{"ftp://127.0.0.1", "only http and https addresses"},
		{"http://anna:hunter2@127.0.0.1:" + port, "holds a user name or password"},
		{"http://127.0.0.1:99999", "is not a port"},
	} {
		code, out, errOut := h.run(h.liveArgs(tc.arg)...)
		if code != exitError || !strings.Contains(errOut, tc.want) {
			t.Errorf("live %s: exit = %d, want %d and %q\nstdout:\n%s\nstderr:\n%s", tc.arg, code, exitError, tc.want, out, errOut)
		}
		if strings.Contains(out+errOut, "hunter2") {
			t.Errorf("live %s repeats the password:\n%s", tc.arg, errOut)
		}
	}
	if code, _, errOut := h.run(h.liveArgs()...); code != exitError || !strings.Contains(errOut, "name the address to check") {
		t.Errorf("live without an address: exit = %d\n%s", code, errOut)
	}
	if hits.Load() != 0 {
		t.Error("a refused check contacted the system")
	}
}

func TestLiveWhenNothingAnswers(t *testing.T) {
	h := newHarness(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "deploying", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	h.writeScope(`"hosts": ["127.0.0.1"], "ports": [` + closed + `, ` + portString(t, down.URL) + `]`)

	code, out, errOut := h.run(h.liveArgs("http://127.0.0.1:" + closed)...)
	if code != exitError || !strings.Contains(errOut, "nothing answered on port "+closed) || !strings.Contains(errOut, "-wait") {
		t.Errorf("closed port: exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	code, out, errOut = h.run(h.liveArgs(down.URL)...)
	if code != exitError || !strings.Contains(errOut, "it answered with status 503") {
		t.Errorf("503: exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	code, out, errOut = h.run(h.liveArgs("-wait", "50ms", down.URL)...)
	if code != exitError || !strings.Contains(errOut, "waited 50ms") {
		t.Errorf("503 with -wait: exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
}

func TestLiveWaitsForTheSystem(t *testing.T) {
	h := newHarness(t)
	var requests atomic.Int32
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= 3 {
			http.Error(w, "deploying", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, `<html><head><title>Ready</title></head></html>`)
	}))
	defer site.Close()
	h.writeScope(`"hosts": ["127.0.0.1"], "ports": [` + portString(t, site.URL) + `]`)

	code, out, errOut := h.run(h.liveArgs("-wait", "30s", "-no-checks", site.URL)...)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
	if !strings.Contains(errOut, "Waiting: "+site.URL+": it answered with status 503.") {
		t.Errorf("stderr does not say what it waits for:\n%s", errOut)
	}
	if !strings.Contains(out, `Answer: 200 "Ready"`) || !strings.Contains(out, "Nothing found.") {
		t.Errorf("stdout:\n%s", out)
	}
}
