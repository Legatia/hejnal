package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/scope"
)

const (
	// maxRuns is how many runs GET /v1/runs/{id} remembers.
	maxRuns = 50
	// runTimeout stops a run that hangs. Real scopes finish well within it.
	runTimeout = 2 * time.Hour
)

// Run statuses.
const (
	statusRunning   = "running"
	statusSucceeded = "succeeded"
	statusFailed    = "failed"
)

// errRunsOff answers run requests when the server does not allow runs.
const errRunsOff = "this server does not start runs: it was started without allowing them"

// runInfo describes a run for GET /v1/runs/{id}.
type runInfo struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	// Counts, once the run has succeeded: all findings, and the findings
	// new and resolved since the last report.
	Findings *int `json:"findings,omitempty"`
	Added    *int `json:"added,omitempty"`
	Resolved *int `json:"resolved,omitempty"`
	// First is set when nothing had been reported before the run.
	First bool `json:"first,omitempty"`
}

// runList remembers recent runs and lets only one run at a time.
type runList struct {
	mu      sync.Mutex
	byID    map[string]runInfo
	order   []string // oldest first
	current string   // the run in progress, if any
}

// start records a new run, or returns the ID of the run in progress.
func (l *runList) start(now time.Time) (info runInfo, busy string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current != "" {
		return runInfo{}, l.current
	}
	if l.byID == nil {
		l.byID = map[string]runInfo{}
	}
	info = runInfo{ID: rand.Text(), Status: statusRunning, StartedAt: now.UTC()}
	l.byID[info.ID] = info
	l.order = append(l.order, info.ID)
	// Only the newest run can be in progress, so pruning the oldest is safe.
	for len(l.order) > maxRuns {
		delete(l.byID, l.order[0])
		l.order = l.order[1:]
	}
	l.current = info.ID
	return info, ""
}

// finish records how a run ended and allows the next one.
func (l *runList) finish(id string, now time.Time, res *engine.Result, err error) runInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	info := l.byID[id]
	end := now.UTC()
	info.FinishedAt = &end
	if err != nil {
		info.Status, info.Error = statusFailed, err.Error()
	} else {
		findings, added, resolved := len(res.Snapshot.Findings), len(res.Changes.Added), len(res.Changes.Resolved)
		info.Status = statusSucceeded
		info.Findings, info.Added, info.Resolved = &findings, &added, &resolved
		info.First = res.Changes.First
	}
	l.byID[id] = info
	if l.current == id {
		l.current = ""
	}
	return info
}

func (l *runList) get(id string) (runInfo, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, ok := l.byID[id]
	return info, ok
}

// startRun serves POST /v1/runs. It starts a run in the background with the
// scope configured on the server and answers 202 with the run's ID.
func (h *handler) startRun(w http.ResponseWriter, r *http.Request) {
	if !h.allowRuns {
		writeError(w, http.StatusForbidden, errRunsOff)
		return
	}
	if _, err := params(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := noParameters(r.Body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sc, err := h.scope()
	if err == nil && sc == nil {
		err = errors.New("no scope is configured")
	}
	if err != nil {
		h.logf("api: cannot start a run: %v", err)
		writeError(w, http.StatusInternalServerError, "cannot start a run: "+err.Error())
		return
	}
	info, busy := h.runs.start(h.now())
	if busy != "" {
		writeError(w, http.StatusConflict, fmt.Sprintf("run %s is still in progress; follow it at /v1/runs/%s", busy, busy))
		return
	}
	h.logf("api: run %s started for %s", info.ID, sc.Organization)
	go h.execute(info.ID, sc)
	w.Header().Set("Location", "/v1/runs/"+info.ID)
	writeJSON(w, http.StatusAccepted, info)
}

// execute runs the engine and records the outcome. It never marks findings
// as reported. A run is not tied to the request that started it, so it keeps
// going after the response and ends with the process at the latest.
func (h *handler) execute(id string, sc *scope.Scope) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	var (
		res *engine.Result
		err error
	)
	defer func() {
		// A crash must not take the API down or block every later run.
		if p := recover(); p != nil {
			h.logf("api: run %s crashed: %v\n%s", id, p, debug.Stack())
			res, err = nil, fmt.Errorf("the run stopped on an internal error: %v", p)
		}
		info := h.runs.finish(id, h.now(), res, err)
		if err != nil {
			h.logf("api: run %s failed: %v", id, err)
			return
		}
		h.logf("api: run %s finished: %d findings, %d new and %d resolved since the last report", id, *info.Findings, *info.Added, *info.Resolved)
	}()
	res, err = h.engine.Run(ctx, sc)
}

// getRun serves GET /v1/runs/{id}.
func (h *handler) getRun(w http.ResponseWriter, r *http.Request) {
	if !h.allowRuns {
		writeError(w, http.StatusForbidden, errRunsOff)
		return
	}
	if _, err := params(r); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, ok := h.runs.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no run with this ID: the server remembers its last %d runs until it restarts", maxRuns))
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// noParameters accepts an empty body or an empty JSON object. A run always
// checks the scope configured on the server.
func noParameters(body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) == nil && len(fields) == 0 {
		return nil
	}
	return errors.New("a run takes no parameters: it checks the scope configured on the server, so send an empty body or {}")
}
