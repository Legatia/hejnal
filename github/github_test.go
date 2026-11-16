package github_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/github"
	"github.com/Legatia/hejnal/github/githubtest"
)

var now = time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*githubtest.Server, *github.Client) {
	t.Helper()
	srv := githubtest.New("acme/infra", now)
	t.Cleanup(srv.Close)
	c := &github.Client{HTTP: srv.Client(), BaseURL: srv.URL + "/", Token: githubtest.Token, Repo: "acme/infra", UserAgent: "hejnal/test"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestIssueLifecycle(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()

	repo, err := c.Repository(ctx)
	if err != nil || !repo.Private || !repo.HasIssues || repo.Archived || repo.FullName != "acme/infra" {
		t.Fatalf("repository = %+v, %v", repo, err)
	}

	is, unassigned, err := c.Create(ctx, github.NewIssue{Title: "Fix it", Body: "body", Labels: []string{"hejnal"}, Assignees: []string{"anna"}})
	if err != nil || unassigned || is.Number != 1 || !is.Open() || is.URL == "" || !is.HasLabel("Hejnal") || is.HasLabel("bug") {
		t.Fatalf("create = %+v, %v, %v", is, unassigned, err)
	}
	if got := srv.Issue(1); got.Title != "Fix it" || !slices.Equal(got.Labels, []string{"hejnal"}) || !slices.Equal(got.Assignees, []string{"anna"}) {
		t.Errorf("stored issue = %+v", got)
	}

	if err := c.Comment(ctx, 1, "No longer found."); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx, 1, github.NotPlanned); err != nil {
		t.Fatal(err)
	}
	list, err := c.Issues(ctx, "hejnal")
	if err != nil || len(list) != 1 {
		t.Fatalf("issues = %+v, %v", list, err)
	}
	got := list[0]
	if got.Open() || got.StateReason != github.NotPlanned || got.ClosedAt == nil || !got.ClosedAt.Equal(now) || got.Body != "body" {
		t.Errorf("closed issue = %+v", got)
	}
	if c := srv.Issue(1).Comments; !slices.Equal(c, []string{"No longer found."}) {
		t.Errorf("comments = %q", c)
	}

	if err := c.Reopen(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if list, _ := c.Issues(ctx, "hejnal"); !list[0].Open() || list[0].ClosedAt != nil {
		t.Errorf("reopened issue = %+v", list[0])
	}
}

func TestIssuesPagesAndSkipsPullRequests(t *testing.T) {
	srv, c := setup(t)
	for i := range 230 {
		srv.Add(githubtest.Issue{Title: fmt.Sprint("Item ", i), Labels: []string{"hejnal"}, PullRequest: i%100 == 7})
	}
	srv.Add(githubtest.Issue{Title: "Someone else's", Labels: []string{"bug"}})
	list, err := c.Issues(context.Background(), "hejnal")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 227 || list[0].Number != 230 || list[len(list)-1].Number != 1 {
		t.Errorf("got %d issues, first #%d, last #%d", len(list), list[0].Number, list[len(list)-1].Number)
	}
	if reqs := srv.Requests(); len(reqs) != 3 {
		t.Errorf("requests = %q, want three pages", reqs)
	}
}

func TestCreateWithoutAssignee(t *testing.T) {
	srv, c := setup(t)
	srv.SetAssignable("anna")
	is, unassigned, err := c.Create(context.Background(), github.NewIssue{Title: "Fix it", Assignees: []string{"nobody"}})
	if err != nil || !unassigned || is.Number != 1 {
		t.Fatalf("create = %+v, %v, %v", is, unassigned, err)
	}
	if a := srv.Issue(1).Assignees; len(a) != 0 {
		t.Errorf("assignees = %q", a)
	}
	// A refusal that is not about the assignee is still an error.
	if _, _, err := c.Create(context.Background(), github.NewIssue{Assignees: []string{"anna"}}); err == nil {
		t.Error("an issue without a title was created")
	}
}

func TestErrors(t *testing.T) {
	srv, c := setup(t)
	ctx := context.Background()

	srv.Fail("GET /repos/acme/infra", http.StatusForbidden)
	_, err := c.Repository(ctx)
	var ge *github.Error
	if !errors.As(err, &ge) || ge.Status != http.StatusForbidden || ge.RateLimited {
		t.Fatalf("error = %v", err)
	}
	want := "GitHub answered 403 Forbidden to GET /repos/acme/infra: Server says no [31m really. The token needs permission to read and write issues in the repository"
	if err.Error() != want {
		t.Errorf("error = %q\nwant    %q", err, want)
	}

	srv.Fail("GET /repos/acme/infra/issues", http.StatusTooManyRequests)
	if _, err := c.Issues(ctx, "hejnal"); !errors.As(err, &ge) || !ge.RateLimited || !strings.Contains(err.Error(), "run it again later") {
		t.Errorf("rate limit error = %v", err)
	}

	bad := *c
	bad.Token = "wrong"
	if _, err := bad.Repository(ctx); err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "HEJNAL_GITHUB_TOKEN") || strings.Contains(err.Error(), "wrong") {
		t.Errorf("bad token error = %v", err)
	}

	other := *c
	other.Repo = "acme/other"
	if _, err := other.Repository(ctx); err == nil || !strings.Contains(err.Error(), "Check the repository's name") {
		t.Errorf("unknown repository error = %v", err)
	}

	gone := *c
	gone.BaseURL = "http://127.0.0.1:1"
	if _, err := gone.Repository(ctx); err == nil || strings.Contains(err.Error(), githubtest.Token) {
		t.Errorf("connection error = %v", err)
	}
}

func TestValidate(t *testing.T) {
	ok := github.Client{Repo: "Legatia/hejnal", Token: "t"}
	if err := ok.Validate(); err != nil {
		t.Errorf("default API: %v", err)
	}
	cases := []struct {
		name string
		c    github.Client
		want string
	}{
		{"no repo", github.Client{Token: "t"}, "owner/name"},
		{"bare name", github.Client{Repo: "hejnal", Token: "t"}, "owner/name"},
		{"path", github.Client{Repo: "a/b/c", Token: "t"}, "owner/name"},
		{"dots", github.Client{Repo: "a/..", Token: "t"}, "owner/name"},
		{"query", github.Client{Repo: "a/b?x=1", Token: "t"}, "owner/name"},
		{"no token", github.Client{Repo: "a/b"}, "no GitHub token"},
		{"plain http", github.Client{Repo: "a/b", Token: "t", BaseURL: "http://github.example.com/api/v3"}, "must use https"},
		{"not a URL", github.Client{Repo: "a/b", Token: "t", BaseURL: "github.example.com"}, "is not a URL"},
		{"credentials", github.Client{Repo: "a/b", Token: "t", BaseURL: "https://user:pw@github.example.com"}, "is not a URL"},
	}
	for _, tc := range cases {
		if err := tc.c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	for _, base := range []string{"https://github.example.com/api/v3", "http://localhost:8080", "http://[::1]:8080"} {
		c := github.Client{Repo: "a/b", Token: "t", BaseURL: base}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
}

func TestPauseBetweenChanges(t *testing.T) {
	_, c := setup(t)
	c.Pause = 40 * time.Millisecond
	ctx := context.Background()
	start := time.Now()
	for range 3 {
		if _, _, err := c.Create(ctx, github.NewIssue{Title: "Fix it"}); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 80*time.Millisecond {
		t.Errorf("three changes took %v, want two pauses", d)
	}
	// Reading does not wait.
	start = time.Now()
	if _, err := c.Issues(ctx, "hejnal"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 30*time.Millisecond {
		t.Errorf("a read waited %v", d)
	}

	c.Pause = time.Hour
	ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, _, err := c.Create(ctx, github.NewIssue{Title: "Fix it"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want the deadline", err)
	}
}
