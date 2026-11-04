package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
)

// waitRun polls a run until it is no longer running.
func waitRun(t *testing.T, srv *httptest.Server, id string) runInfo {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, _, body := do(t, srv, http.MethodGet, "/v1/runs/"+id, testToken, nil)
		if status != http.StatusOK {
			t.Fatalf("GET run %s: %d %s", id, status, body)
		}
		info := decode[runInfo](t, body)
		if info.Status != statusRunning {
			return info
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s is still running", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunLifecycle(t *testing.T) {
	site := newSite(t, true)
	dir := t.TempDir()
	e := newEngine(t, dir, kevSample)
	srv, logs := newAPI(t, Config{Engine: e, Scope: siteScope(t, site.URL), AllowRuns: true})

	status, hdr, body := do(t, srv, http.MethodPost, "/v1/runs", testToken, nil)
	if status != http.StatusAccepted {
		t.Fatalf("POST /v1/runs: %d %s", status, body)
	}
	run := decode[map[string]any](t, body)
	id, _ := run["id"].(string)
	if id == "" || run["status"] != "running" {
		t.Fatalf("start response = %s", body)
	}
	if loc := hdr.Get("Location"); loc != "/v1/runs/"+id {
		t.Errorf("Location = %q", loc)
	}

	// The site holds the run's request, so the run is still in progress.
	site.waitHit(t)
	status, _, body = do(t, srv, http.MethodPost, "/v1/runs", testToken, nil)
	if status != http.StatusConflict || !strings.Contains(errorText(t, body), id) {
		t.Errorf("second POST while running: %d %s", status, body)
	}
	status, _, body = do(t, srv, http.MethodGet, "/v1/runs/"+id, testToken, nil)
	info := decode[runInfo](t, body)
	if status != http.StatusOK || info.Status != statusRunning || info.FinishedAt != nil || info.Findings != nil {
		t.Errorf("status while running: %d %s", status, body)
	}

	site.unblock()
	info = waitRun(t, srv, id)
	if info.Status != statusSucceeded || info.Error != "" || info.FinishedAt == nil || !info.StartedAt.Equal(testNow) {
		t.Fatalf("finished run = %+v", info)
	}
	if info.Findings == nil || *info.Findings != 6 || *info.Added != 6 || *info.Resolved != 0 || !info.First {
		t.Errorf("counts: findings %v added %v resolved %v first %v", deref(info.Findings), deref(info.Added), deref(info.Resolved), info.First)
	}
	// Runs through the API never mark findings as reported.
	if snap, err := e.Store().LoadReported(); snap != nil || err != nil {
		t.Errorf("the run marked findings as reported: %v %v", snap, err)
	}

	// Its results are served.
	_, _, body = do(t, srv, http.MethodGet, "/v1/findings?min_severity=critical&host=127.0.0.1", testToken, nil)
	got := decode[findingsResponse](t, body)
	if len(got.Findings) != 3 || !strings.Contains(string(body), "CVE-2026-119977") || got.KEVVersion != "2026.11.03" {
		t.Errorf("findings after the run: %s", body)
	}
	_, _, body = do(t, srv, http.MethodGet, "/v1/changes", testToken, nil)
	if ch := decode[changesResponse](t, body); !ch.First || len(ch.Added) != 6 {
		t.Errorf("changes after the run: %s", body)
	}

	// The next run can start once the first one is done.
	status, _, body = do(t, srv, http.MethodPost, "/v1/runs", testToken, strings.NewReader("{}"))
	if status != http.StatusAccepted {
		t.Fatalf("POST after the run: %d %s", status, body)
	}
	second := decode[runInfo](t, body)
	if second.ID == id {
		t.Errorf("run IDs repeat: %s", id)
	}
	if info := waitRun(t, srv, second.ID); info.Status != statusSucceeded || !info.First {
		t.Errorf("second run = %+v", info)
	}

	if status, _, body := do(t, srv, http.MethodGet, "/v1/runs/nope", testToken, nil); status != http.StatusNotFound {
		t.Errorf("unknown run: %d %s", status, body)
	}
	log := logs.String()
	for _, want := range []string{"run " + id + " started for Sklep Sp. z o.o.", "run " + id + " finished: 6 findings, 6 new"} {
		if !strings.Contains(log, want) {
			t.Errorf("log is missing %q:\n%s", want, log)
		}
	}
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestRunFailure(t *testing.T) {
	site := newSite(t, false)
	e := newEngine(t, t.TempDir(), filepath.Join(t.TempDir(), "missing-kev.json"))
	srv, logs := newAPI(t, Config{Engine: e, Scope: siteScope(t, site.URL), AllowRuns: true})
	status, _, body := do(t, srv, http.MethodPost, "/v1/runs", testToken, nil)
	if status != http.StatusAccepted {
		t.Fatalf("POST: %d %s", status, body)
	}
	id := decode[runInfo](t, body).ID
	info := waitRun(t, srv, id)
	if info.Status != statusFailed || !strings.Contains(info.Error, "missing-kev.json") || info.FinishedAt == nil || info.Findings != nil {
		t.Errorf("failed run = %+v", info)
	}
	if !strings.Contains(logs.String(), "run "+id+" failed") {
		t.Errorf("failure not logged:\n%s", logs.String())
	}
	// A failed run does not block the next one.
	if status, _, body := do(t, srv, http.MethodPost, "/v1/runs", testToken, nil); status != http.StatusAccepted {
		t.Errorf("POST after a failure: %d %s", status, body)
	} else {
		waitRun(t, srv, decode[runInfo](t, body).ID)
	}
}

func TestRunNeedsAScope(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		scope func() (*scope.Scope, error)
		want  string
	}{
		{func() (*scope.Scope, error) { return nil, errors.New("scope: authorization.confirmedBy is required") }, "confirmedBy is required"},
		{func() (*scope.Scope, error) { return nil, nil }, "no scope is configured"},
	} {
		srv, _ := newAPI(t, Config{Engine: newEngine(t, dir, kevSample), Scope: c.scope, AllowRuns: true})
		status, _, body := do(t, srv, http.MethodPost, "/v1/runs", testToken, nil)
		msg := errorText(t, body)
		if status != http.StatusInternalServerError || !strings.Contains(msg, "cannot start a run") || !strings.Contains(msg, c.want) {
			t.Errorf("%d %q, want it to mention %q", status, msg, c.want)
		}
	}
}

func TestRunTakesNoParameters(t *testing.T) {
	srv, _ := newAPI(t, Config{Engine: newEngine(t, t.TempDir(), kevSample), Scope: siteScope(t, "http://127.0.0.1:1"), AllowRuns: true})
	for _, body := range []string{`{"scope": "other.json"}`, `[]`, `not json`} {
		status, _, resp := do(t, srv, http.MethodPost, "/v1/runs", testToken, strings.NewReader(body))
		if status != http.StatusBadRequest || !strings.Contains(errorText(t, resp), "no parameters") {
			t.Errorf("body %s: %d %s", body, status, resp)
		}
	}
	if status, _, _ := do(t, srv, http.MethodPost, "/v1/runs?scope=x", testToken, nil); status != http.StatusBadRequest {
		t.Errorf("query parameter: %d", status)
	}
}

func TestRunsRefusedWhenNotAllowed(t *testing.T) {
	dir := t.TempDir()
	// An engine and a scope alone do not allow runs.
	srv, _ := newAPI(t, Config{Store: state.Store{Dir: dir}, Engine: newEngine(t, dir, kevSample), Scope: siteScope(t, "http://127.0.0.1:1")})
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/v1/runs"},
		{http.MethodGet, "/v1/runs/abc"},
	} {
		if status, _, _ := do(t, srv, c.method, c.path, "", nil); status != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: %d", c.method, c.path, status)
		}
		status, _, body := do(t, srv, c.method, c.path, testToken, nil)
		if status != http.StatusForbidden || !strings.Contains(errorText(t, body), "does not start runs") {
			t.Errorf("%s %s: %d %s", c.method, c.path, status, body)
		}
	}
	if _, err := (state.Store{Dir: dir}).LoadInventory(); !errors.Is(err, state.ErrNoInventory) {
		t.Errorf("a refused run still ran: %v", err)
	}
}

func TestRunListPrunesOldRuns(t *testing.T) {
	var l runList
	var first string
	for i := range maxRuns + 5 {
		info, busy := l.start(testNow)
		if busy != "" {
			t.Fatalf("run %d: busy with %s", i, busy)
		}
		if i == 0 {
			first = info.ID
		}
		if _, busy := l.start(testNow); busy != info.ID {
			t.Fatalf("second start while %s runs: busy = %q", info.ID, busy)
		}
		l.finish(info.ID, testNow, nil, errors.New("stopped"))
	}
	if len(l.byID) != maxRuns || len(l.order) != maxRuns {
		t.Errorf("remembers %d runs, want %d", len(l.byID), maxRuns)
	}
	if _, ok := l.get(first); ok {
		t.Error("the oldest run is still remembered")
	}
}
