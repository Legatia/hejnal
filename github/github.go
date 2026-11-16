// Package github opens, comments on, closes and reopens issues in one GitHub
// repository through GitHub's REST API.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultAPI is the API of github.com. GitHub Enterprise Server has its own,
// such as https://github.example.com/api/v3.
const DefaultAPI = "https://api.github.com"

// DefaultPause is the wait between two changes. GitHub asks clients that
// create content to leave at least a second between requests.
const DefaultPause = time.Second

const (
	perPage = 100
	// maxPages bounds how many issues with the label are read.
	maxPages = 50
	// maxBody bounds a response: a page of issues with long descriptions.
	maxBody = 32 << 20
)

// Reasons for closing an issue.
const (
	Completed  = "completed"
	NotPlanned = "not_planned"
)

// Client talks to one repository. The token is sent only to BaseURL.
type Client struct {
	HTTP *http.Client
	// BaseURL is the API's address, DefaultAPI if empty.
	BaseURL string
	// Token is a GitHub token that may read and write the repository's
	// issues.
	Token string
	// Repo is the repository as owner/name.
	Repo      string
	UserAgent string
	// Pause is the wait between two changes.
	Pause time.Duration

	lastWrite time.Time
}

// Repository is what the client needs to know about the repository.
type Repository struct {
	FullName  string `json:"full_name"`
	Private   bool   `json:"private"`
	Archived  bool   `json:"archived"`
	HasIssues bool   `json:"has_issues"`
}

// Issue is an issue as GitHub returns it.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	// State is "open" or "closed", and StateReason says why it was closed:
	// Completed or NotPlanned.
	State       string     `json:"state"`
	StateReason string     `json:"state_reason"`
	CreatedAt   time.Time  `json:"created_at"`
	ClosedAt    *time.Time `json:"closed_at"`
	URL         string     `json:"html_url"`
	Labels      []Label    `json:"labels"`
	// PullRequest is set on pull requests, which the issue list includes.
	PullRequest json.RawMessage `json:"pull_request,omitempty"`
}

// Label is a label on an issue.
type Label struct {
	Name string `json:"name"`
}

// Open reports whether the issue is open.
func (i Issue) Open() bool { return i.State == "open" }

// HasLabel reports whether the issue carries a label. GitHub compares label
// names without regard to case.
func (i Issue) HasLabel(name string) bool {
	return slices.ContainsFunc(i.Labels, func(l Label) bool { return strings.EqualFold(l.Name, name) })
}

// NewIssue is an issue to open.
type NewIssue struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Labels    []string `json:"labels,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
}

// Error is a response from GitHub that says the request failed.
type Error struct {
	Method, Path string
	Status       int
	Message      string
	// RateLimited is set when GitHub asks the client to slow down.
	RateLimited bool
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("GitHub answered %d %s to %s %s", e.Status, http.StatusText(e.Status), e.Method, e.Path)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	switch {
	case e.RateLimited:
		msg += ". GitHub's request limit is used up; run it again later"
	case e.Status == http.StatusUnauthorized:
		msg += ". Check the token in HEJNAL_GITHUB_TOKEN or GITHUB_TOKEN"
	case e.Status == http.StatusForbidden:
		msg += ". The token needs permission to read and write issues in the repository"
	case e.Status == http.StatusNotFound:
		msg += ". Check the repository's name, and that the token may see it"
	case e.Status == http.StatusGone:
		msg += ". Issues are turned off in the repository"
	}
	return msg
}

var repoRE = regexp.MustCompile(`^[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38}/[A-Za-z0-9._-]{1,100}$`)

// ValidRepo reports whether s names a repository as owner/name.
func ValidRepo(s string) bool {
	_, name, _ := strings.Cut(s, "/")
	return repoRE.MatchString(s) && name != "." && name != ".."
}

// Validate checks the client's settings before any request is made.
func (c *Client) Validate() error {
	if !ValidRepo(c.Repo) {
		return fmt.Errorf("repository %q must look like owner/name", c.Repo)
	}
	if c.Token == "" {
		return errors.New("no GitHub token")
	}
	u, err := url.Parse(c.base())
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("GitHub API address %q is not a URL", c.base())
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopback(u.Hostname()):
		// A test server on this machine.
	default:
		return fmt.Errorf("GitHub API address %q must use https, so the token is not sent in the clear", c.base())
	}
	return nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) base() string {
	if c.BaseURL == "" {
		return DefaultAPI
	}
	return strings.TrimRight(c.BaseURL, "/")
}

// Repository reads the repository: whether it is private, and whether it
// takes issues.
func (c *Client) Repository(ctx context.Context) (Repository, error) {
	var r Repository
	err := c.do(ctx, http.MethodGet, "/repos/"+c.Repo, nil, nil, &r)
	return r, err
}

// Issues lists the repository's issues that carry a label, open and closed,
// newest first. Pull requests are left out.
func (c *Client) Issues(ctx context.Context, label string) ([]Issue, error) {
	var out []Issue
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("more than %d issues in %s carry the label %q; use a label of its own for Hejnal", maxPages*perPage, c.Repo, label)
		}
		q := url.Values{
			"labels":   {label},
			"state":    {"all"},
			"per_page": {strconv.Itoa(perPage)},
			"page":     {strconv.Itoa(page)},
		}
		var batch []Issue
		if err := c.do(ctx, http.MethodGet, "/repos/"+c.Repo+"/issues", q, nil, &batch); err != nil {
			return nil, err
		}
		for _, is := range batch {
			if len(is.PullRequest) == 0 {
				out = append(out, is)
			}
		}
		if len(batch) < perPage {
			return out, nil
		}
	}
}

// Create opens an issue. GitHub refuses an issue whose assignee cannot be
// assigned in the repository; Create then opens it without assignees and
// reports that with unassigned.
func (c *Client) Create(ctx context.Context, n NewIssue) (is Issue, unassigned bool, err error) {
	path := "/repos/" + c.Repo + "/issues"
	err = c.do(ctx, http.MethodPost, path, nil, n, &is)
	var ge *Error
	if len(n.Assignees) > 0 && errors.As(err, &ge) && ge.Status == http.StatusUnprocessableEntity {
		n.Assignees = nil
		err = c.do(ctx, http.MethodPost, path, nil, n, &is)
		unassigned = err == nil
	}
	return is, unassigned, err
}

// Comment adds a comment to an issue.
func (c *Client) Comment(ctx context.Context, number int, body string) error {
	return c.do(ctx, http.MethodPost, c.issue(number)+"/comments", nil, map[string]string{"body": body}, nil)
}

// Close closes an issue as Completed or NotPlanned.
func (c *Client) Close(ctx context.Context, number int, reason string) error {
	return c.do(ctx, http.MethodPatch, c.issue(number), nil, map[string]string{"state": "closed", "state_reason": reason}, nil)
}

// Reopen opens a closed issue again.
func (c *Client) Reopen(ctx context.Context, number int) error {
	return c.do(ctx, http.MethodPatch, c.issue(number), nil, map[string]string{"state": "open", "state_reason": "reopened"}, nil)
}

func (c *Client) issue(number int) string {
	return "/repos/" + c.Repo + "/issues/" + strconv.Itoa(number)
}

// do sends one request and decodes the answer into out, if out is not nil.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	if method != http.MethodGet {
		if err := c.pause(ctx); err != nil {
			return err
		}
	}
	target := c.base() + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("GitHub: %s %s: %w", method, path, err)
	}
	if len(data) > maxBody {
		return fmt.Errorf("GitHub: the answer to %s %s is too large", method, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{Method: method, Path: path, Status: resp.StatusCode}
		var msg struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &msg) == nil {
			e.Message = oneLine(msg.Message)
		}
		limited := resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""
		e.RateLimited = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden && limited
		return e
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("GitHub: the answer to %s %s is not what the API documents: %w", method, path, err)
	}
	return nil
}

// pause waits until Pause has passed since the last change.
func (c *Client) pause(ctx context.Context) error {
	if wait := time.Until(c.lastWrite.Add(c.Pause)); wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	c.lastWrite = time.Now()
	return nil
}

// oneLine keeps a message from GitHub to one short line of printable text.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
	const limit = 200
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "…"
	}
	return s
}
