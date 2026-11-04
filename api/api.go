// Package api serves Hejnal's results over a small REST API, for dashboards,
// ticketing systems and scripts.
//
// The API reads the state directory that runs write. Every endpoint except
// GET /v1/health needs the bearer token. When the server allows it, clients
// can also start a run. The API never marks findings as reported, so the
// command line still announces them as new.
//
//	GET  /v1/health           status and version, without a token
//	GET  /v1/findings         latest findings; filters: min_severity, kind, host
//	GET  /v1/groups           items to fix, as in the fix list; filter: min_severity
//	GET  /v1/inventory        hosts, services and products found
//	GET  /v1/changes          new and resolved since the last report
//	GET  /v1/reports/fixlist  the fix list in Markdown; lang=en or pl
//	GET  /v1/reports/nis2     a NIS2 early-warning draft in Markdown; lang=en or pl
//	POST /v1/runs             start a run in the background, when allowed
//	GET  /v1/runs/{id}        how a run is going
//
// Errors are JSON objects with an "error" message.
package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
)

// MinTokenLength is the shortest bearer token NewHandler accepts.
const MinTokenLength = 32

// maxBody is the largest request body the API accepts, in bytes.
const maxBody = 1 << 10

// Config configures the API.
type Config struct {
	// Store is the state directory to serve. When it is empty, the engine's
	// state directory is used.
	Store state.Store
	// Token is the bearer token every client must send: at least
	// MinTokenLength printable ASCII characters, without spaces.
	Token string
	// Engine runs checks. It is needed only when AllowRuns is set.
	Engine *engine.Engine
	// Scope returns the scope for a new run. It is called for every run, so
	// edits to the scope file apply to the next one. It is needed only when
	// AllowRuns is set.
	Scope func() (*scope.Scope, error)
	// AllowRuns lets clients start runs with POST /v1/runs.
	AllowRuns bool
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// Logf receives log messages, possibly from several goroutines at once.
	// By default they are discarded.
	Logf func(format string, args ...any)
}

type handler struct {
	store     state.Store
	tokenHash [sha256.Size]byte
	// changeEngine tells what changed since the last report. It is the
	// configured engine, or one made only for that.
	changeEngine *engine.Engine
	engine       *engine.Engine
	scope        func() (*scope.Scope, error)
	allowRuns    bool
	now          func() time.Time
	logf         func(string, ...any)
	runs         runList
}

// NewHandler returns the API as an http.Handler. It fails if the token is
// shorter than MinTokenLength, if AllowRuns is set without both Engine and
// Scope, or if there is no state directory or it is not the engine's.
func NewHandler(cfg Config) (http.Handler, error) {
	if err := checkToken(cfg.Token); err != nil {
		return nil, err
	}
	if cfg.AllowRuns && (cfg.Engine == nil || cfg.Scope == nil) {
		return nil, errors.New("api: allowing runs needs both an engine and a scope")
	}
	store, err := storeFor(cfg.Store, cfg.Engine)
	if err != nil {
		return nil, err
	}
	changeEngine := cfg.Engine
	if changeEngine == nil {
		// Creating an engine does no network or disk I/O. This one only
		// compares findings with the last report, exactly as runs do.
		if changeEngine, err = engine.New(engine.Config{StateDir: store.Dir}); err != nil {
			return nil, fmt.Errorf("api: %w", err)
		}
	}
	h := &handler{
		store:        store,
		tokenHash:    sha256.Sum256([]byte(cfg.Token)),
		changeEngine: changeEngine,
		engine:       cfg.Engine,
		scope:        cfg.Scope,
		allowRuns:    cfg.AllowRuns,
		now:          cfg.Now,
		logf:         cfg.Logf,
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.logf == nil {
		h.logf = func(string, ...any) {}
	}
	return h.routes(), nil
}

func checkToken(token string) error {
	if len(token) < MinTokenLength {
		return fmt.Errorf("api: the token must be at least %d characters long; generate one with `openssl rand -hex 32`", MinTokenLength)
	}
	for i := 0; i < len(token); i++ {
		if c := token[i]; c <= ' ' || c > '~' {
			return errors.New("api: the token may contain only printable ASCII characters, without spaces")
		}
	}
	return nil
}

// storeFor picks the state directory to serve. Results must come from the
// directory runs write to.
func storeFor(s state.Store, e *engine.Engine) (state.Store, error) {
	if e != nil {
		if s.Dir == "" {
			return e.Store(), nil
		}
		if !sameDir(s.Dir, e.Store().Dir) {
			return s, fmt.Errorf("api: Store (%s) is not the engine's state directory (%s)", s.Dir, e.Store().Dir)
		}
	}
	if s.Dir == "" {
		return s, errors.New("api: Store.Dir is required")
	}
	return s, nil
}

func sameDir(a, b string) bool {
	a, errA := filepath.Abs(a)
	b, errB := filepath.Abs(b)
	return errA == nil && errB == nil && a == b
}

func (h *handler) routes() http.Handler {
	mux := http.NewServeMux()
	h.route(mux, http.MethodGet, "/v1/health", h.health, false)
	h.route(mux, http.MethodGet, "/v1/findings", h.findings, true)
	h.route(mux, http.MethodGet, "/v1/groups", h.groups, true)
	h.route(mux, http.MethodGet, "/v1/inventory", h.inventory, true)
	h.route(mux, http.MethodGet, "/v1/changes", h.changes, true)
	h.route(mux, http.MethodGet, "/v1/reports/fixlist", h.report(report.FixList), true)
	h.route(mux, http.MethodGet, "/v1/reports/nis2", h.report(report.NIS2), true)
	h.route(mux, http.MethodPost, "/v1/runs", h.startRun, true)
	h.route(mux, http.MethodGet, "/v1/runs/{id}", h.getRun, true)
	mux.Handle("/", h.authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("there is no endpoint at %s; the API serves /v1/health, /v1/findings, /v1/groups, /v1/inventory, /v1/changes, /v1/reports/fixlist, /v1/reports/nis2 and /v1/runs", r.URL.Path))
	})))
	return h.common(mux)
}

// route registers fn for one method and path, and a JSON "method not
// allowed" answer for other methods on the same path. Private routes need the
// token, including for that answer.
func (h *handler) route(mux *http.ServeMux, method, path string, fn http.HandlerFunc, private bool) {
	var ok, other http.Handler = fn, methodNotAllowed(method)
	if private {
		ok, other = h.authorize(ok), h.authorize(other)
	}
	mux.Handle(method+" "+path, ok)
	mux.Handle(path, other)
}

func methodNotAllowed(method string) http.HandlerFunc {
	allow := method
	if method == http.MethodGet {
		allow = "GET, HEAD"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, fmt.Sprintf("use %s for %s", method, r.URL.Path))
	}
}

// common sets the headers every response carries and rejects request bodies
// over maxBody, before anything else runs.
func (h *handler) common(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.ContentLength > maxBody {
			writeError(w, http.StatusRequestEntityTooLarge, "request bodies are limited to 1 KiB")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeError(w, http.StatusRequestEntityTooLarge, "request bodies are limited to 1 KiB")
				return
			}
			writeError(w, http.StatusBadRequest, "could not read the request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// authorize lets requests through only with the right bearer token. Tokens
// are compared as SHA-256 hashes in constant time, so neither the content nor
// the length of the token leaks through timing.
func (h *handler) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, found := bearerToken(r.Header.Get("Authorization"))
		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(sum[:], h.tokenHash[:]) != 1 || !found {
			reason := "no bearer token"
			if found {
				reason = "wrong token"
			}
			// Never log the token itself.
			h.logf("api: refused %s %q from %s: %s", r.Method, r.URL.Path, r.RemoteAddr, reason)
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "send the API token in an \"Authorization: Bearer <token>\" header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

type errorBody struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		status = http.StatusInternalServerError
		data = []byte(`{"error": "could not encode the response"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}
