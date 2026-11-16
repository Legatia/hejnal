// Package githubtest is a stand-in for GitHub's issues API, for tests.
package githubtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Token is the token the server accepts.
const Token = "test-token"

// Issue is an issue the server holds.
type Issue struct {
	Number      int
	Title, Body string
	Labels      []string
	Assignees   []string
	Closed      bool
	Reason      string
	CreatedAt   time.Time
	ClosedAt    time.Time
	Comments    []string
	PullRequest bool
}

// Server serves one repository's issues.
type Server struct {
	*httptest.Server
	// Repo is the repository served, as owner/name.
	Repo string

	mu sync.Mutex
	// now is the time the server stamps on what it creates and closes.
	now        time.Time
	public     bool
	archived   bool
	noIssues   bool
	assignable []string
	noLabels   bool
	failures   map[string]int
	issues     []*Issue
	requests   []string
}

// New starts a server for a private repository that takes issues.
func New(repo string, now time.Time) *Server {
	s := &Server{Repo: repo, now: now, failures: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// SetNow sets the time the server stamps on what it creates and closes.
func (s *Server) SetNow(t time.Time) { s.mu.Lock(); s.now = t; s.mu.Unlock() }

// SetPublic makes the repository public or private.
func (s *Server) SetPublic(v bool) { s.mu.Lock(); s.public = v; s.mu.Unlock() }

// SetArchived archives the repository.
func (s *Server) SetArchived(v bool) { s.mu.Lock(); s.archived = v; s.mu.Unlock() }

// SetIssuesOff turns issues off in the repository.
func (s *Server) SetIssuesOff(v bool) { s.mu.Lock(); s.noIssues = v; s.mu.Unlock() }

// SetAssignable names the only logins issues can be assigned to. Without it
// anyone can be assigned.
func (s *Server) SetAssignable(logins ...string) {
	s.mu.Lock()
	s.assignable = append([]string{}, logins...)
	s.mu.Unlock()
}

// SetLabelsDropped makes the server leave the labels off new issues, as
// GitHub does for accounts that may not label issues.
func (s *Server) SetLabelsDropped(v bool) { s.mu.Lock(); s.noLabels = v; s.mu.Unlock() }

// Fail makes the next request with this method and path, such as
// "PATCH /repos/o/r/issues/1", fail with a status.
func (s *Server) Fail(request string, status int) {
	s.mu.Lock()
	s.failures[request] = status
	s.mu.Unlock()
}

// Add puts an issue in the repository and returns its number.
func (s *Server) Add(is Issue) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.add(is).Number
}

func (s *Server) add(is Issue) *Issue {
	is.Number = len(s.issues) + 1
	if is.CreatedAt.IsZero() {
		is.CreatedAt = s.now
	}
	s.issues = append(s.issues, &is)
	return &is
}

// Issue returns a copy of the issue with a number.
func (s *Server) Issue(number int) Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	if number < 1 || number > len(s.issues) {
		return Issue{}
	}
	return *s.issues[number-1]
}

// Issues returns copies of all issues, oldest first.
func (s *Server) Issues() []Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Issue, len(s.issues))
	for i, is := range s.issues {
		out[i] = *is
	}
	return out
}

// CloseIssue closes an issue as a person would, at a time.
func (s *Server) CloseIssue(number int, reason string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	is := s.issues[number-1]
	is.Closed, is.Reason, is.ClosedAt = true, reason, at
}

// Requests returns the requests served so far as "METHOD path", and forgets
// them.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.requests
	s.requests = nil
	return out
}

// Writes returns the requests served so far that change something, and
// forgets all requests.
func (s *Server) Writes() []string {
	var out []string
	for _, r := range s.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	s.requests = append(s.requests, key)
	if r.Header.Get("Authorization") != "Bearer "+Token {
		fail(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	if status, ok := s.failures[key]; ok {
		delete(s.failures, key)
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "60")
		}
		fail(w, status, "Server says no\x1b[31m\nreally")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/repos/"+s.Repo)
	if !ok {
		fail(w, http.StatusNotFound, "Not Found")
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		reply(w, http.StatusOK, map[string]any{"full_name": s.Repo, "private": !s.public, "archived": s.archived, "has_issues": !s.noIssues})
	case rest == "/issues" && r.Method == http.MethodGet:
		s.list(w, r)
	case rest == "/issues" && r.Method == http.MethodPost:
		s.create(w, r)
	case len(parts) == 2 && parts[0] == "issues" && r.Method == http.MethodPatch:
		s.patch(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "issues" && parts[2] == "comments" && r.Method == http.MethodPost:
		s.comment(w, r, parts[1])
	default:
		fail(w, http.StatusNotFound, "Not Found")
	}
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("state") != "all" {
		fail(w, http.StatusUnprocessableEntity, "the test server lists only state=all")
		return
	}
	per, _ := strconv.Atoi(q.Get("per_page"))
	page, _ := strconv.Atoi(q.Get("page"))
	if per < 1 {
		per = 30
	}
	if page < 1 {
		page = 1
	}
	var match []map[string]any
	for _, is := range slices.Backward(s.issues) {
		if slices.ContainsFunc(is.Labels, func(l string) bool { return strings.EqualFold(l, q.Get("labels")) }) {
			match = append(match, view(is))
		}
	}
	from := min((page-1)*per, len(match))
	to := min(from+per, len(match))
	out := match[from:to]
	if out == nil {
		out = []map[string]any{}
	}
	reply(w, http.StatusOK, out)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title     string   `json:"title"`
		Body      string   `json:"body"`
		Labels    []string `json:"labels"`
		Assignees []string `json:"assignees"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Title == "" {
		fail(w, http.StatusUnprocessableEntity, "Validation Failed")
		return
	}
	if s.archived {
		fail(w, http.StatusForbidden, "Repository was archived so is read-only.")
		return
	}
	if s.noIssues {
		fail(w, http.StatusGone, "Issues are disabled for this repo")
		return
	}
	for _, a := range in.Assignees {
		if s.assignable != nil && !slices.Contains(s.assignable, a) {
			fail(w, http.StatusUnprocessableEntity, "Validation Failed")
			return
		}
	}
	if s.noLabels {
		in.Labels = nil
	}
	is := s.add(Issue{Title: in.Title, Body: in.Body, Labels: in.Labels, Assignees: in.Assignees})
	reply(w, http.StatusCreated, view(is))
}

func (s *Server) find(w http.ResponseWriter, number string) *Issue {
	n, err := strconv.Atoi(number)
	if err != nil || n < 1 || n > len(s.issues) {
		fail(w, http.StatusNotFound, "Not Found")
		return nil
	}
	return s.issues[n-1]
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request, number string) {
	is := s.find(w, number)
	if is == nil {
		return
	}
	var in struct {
		State  string `json:"state"`
		Reason string `json:"state_reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusUnprocessableEntity, "Validation Failed")
		return
	}
	switch in.State {
	case "closed":
		is.Closed, is.Reason, is.ClosedAt = true, in.Reason, s.now
	case "open":
		is.Closed, is.Reason, is.ClosedAt = false, in.Reason, time.Time{}
	default:
		fail(w, http.StatusUnprocessableEntity, "Validation Failed")
		return
	}
	reply(w, http.StatusOK, view(is))
}

func (s *Server) comment(w http.ResponseWriter, r *http.Request, number string) {
	is := s.find(w, number)
	if is == nil {
		return
	}
	var in struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Body == "" {
		fail(w, http.StatusUnprocessableEntity, "Validation Failed")
		return
	}
	is.Comments = append(is.Comments, in.Body)
	reply(w, http.StatusCreated, map[string]any{"id": len(is.Comments), "body": in.Body})
}

func view(is *Issue) map[string]any {
	labels := []map[string]any{}
	for _, l := range is.Labels {
		labels = append(labels, map[string]any{"name": l})
	}
	v := map[string]any{
		"labels":       labels,
		"number":       is.Number,
		"title":        is.Title,
		"body":         is.Body,
		"state":        "open",
		"state_reason": nil,
		"created_at":   is.CreatedAt.UTC().Format(time.RFC3339),
		"closed_at":    nil,
		"html_url":     fmt.Sprintf("https://github.test/issues/%d", is.Number),
	}
	if is.Closed {
		v["state"], v["state_reason"], v["closed_at"] = "closed", is.Reason, is.ClosedAt.UTC().Format(time.RFC3339)
	} else if is.Reason != "" {
		v["state_reason"] = is.Reason
	}
	if is.PullRequest {
		v["pull_request"] = map[string]any{"url": "https://github.test/pulls/1"}
	}
	return v
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"message": message})
}
