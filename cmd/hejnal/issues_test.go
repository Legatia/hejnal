package main

import (
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/github/githubtest"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

const issuesRepo = "acme/infra"

// issuesServer starts a stand-in for GitHub and points the command at it
// through the environment, as GitHub Actions does.
func issuesServer(t *testing.T) *githubtest.Server {
	t.Helper()
	srv := githubtest.New(issuesRepo, testNow.Add(time.Minute))
	t.Cleanup(srv.Server.Close)
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_REPOSITORY", issuesRepo)
	t.Setenv("GITHUB_TOKEN", githubtest.Token)
	t.Setenv("HEJNAL_GITHUB_TOKEN", "")
	return srv
}

// scanned makes the harness's first run: WordPress and PHP, both critical.
func scanned(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	if code, _, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run: code %d\n%s", code, errOut)
	}
	return h
}

func (h *harness) issues(args ...string) (int, string, string) {
	return h.run(append([]string{"issues", "-state", h.state, "-scope", h.scope}, args...)...)
}

// editRun saves a later run made at a time: the last one with edit applied.
func (h *harness) editRun(at time.Time, edit func(*state.Snapshot)) {
	h.t.Helper()
	store := state.Store{Dir: h.state}
	snap, err := store.LoadFindings()
	if err != nil {
		h.t.Fatal(err)
	}
	snap.GeneratedAt = at
	edit(snap)
	if err := store.SaveFindings(snap); err != nil {
		h.t.Fatal(err)
	}
}

func withoutPHP(snap *state.Snapshot) {
	snap.Findings = slices.DeleteFunc(snap.Findings, func(f match.Finding) bool { return f.Technology == "PHP" })
}

// wantOutput fails unless out has every line of want, in order.
func wantOutput(t *testing.T, step, out string, want ...string) {
	t.Helper()
	rest := out
	for _, w := range want {
		i := strings.Index(rest, w)
		if i < 0 {
			t.Fatalf("%s: output is missing %q (in this order):\n%s", step, w, out)
		}
		rest = rest[i+len(w):]
	}
}

func TestIssuesFollowTheRuns(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	ids := itemIDs(t, h)
	wp, php := ids["WordPress"], ids["PHP"]

	// The first time, every item gets an issue.
	code, out, errOut := h.issues()
	if code != exitOK {
		t.Fatalf("first: code %d\n%s%s", code, out, errOut)
	}
	wantOutput(t, "first", out,
		"opened #1 · "+wp+" · WordPress on 127.0.0.1:",
		"opened #2 · "+php+" · PHP on 127.0.0.1:",
		"Issues in acme/infra: 2 opened, 0 closed, 0 reopened, 0 open already.")
	first := srv.Issue(1)
	if !strings.HasPrefix(first.Title, "WordPress on 127.0.0.1:") || !slices.Equal(first.Labels, []string{"hejnal"}) || len(first.Assignees) != 0 {
		t.Errorf("issue 1 = %+v", first)
	}
	for _, want := range []string{
		"<!-- hejnal:item:" + wp + " -->\n- **Priority:** critical\n- **Rough effort:** about two hours\n",
		"- **Flaws:**\n  - **CVE-2026-119977**",
		"- **See it yourself:**",
		"`curl -sk -D - -o /dev/null 'http://127.0.0.1:",
		"\n---\nHejnal opened this issue from the run of 2026-11-04.",
	} {
		if !strings.Contains(first.Body, want) {
			t.Errorf("issue 1 is missing %q:\n%s", want, first.Body)
		}
	}
	if strings.Contains(first.Body, "###") {
		t.Errorf("issue 1 repeats its title as a heading:\n%s", first.Body)
	}

	// Nothing changed: nothing is written.
	srv.Requests()
	code, out, _ = h.issues()
	if w := srv.Writes(); code != exitOK || len(w) != 0 || !strings.Contains(out, "0 opened, 0 closed, 0 reopened, 2 open already.") {
		t.Fatalf("second: code %d, writes %q\n%s", code, w, out)
	}

	// A run no longer finds PHP: its issue is closed as completed.
	srv.SetNow(testNow.Add(25 * time.Hour))
	h.editRun(testNow.Add(24*time.Hour), withoutPHP)
	code, out, errOut = h.issues()
	if code != exitOK {
		t.Fatalf("gone: code %d\n%s%s", code, out, errOut)
	}
	wantOutput(t, "gone", out, "closed #2 · "+php+" · PHP on 127.0.0.1:", " · no longer found\n", "0 opened, 1 closed, 0 reopened, 1 open already.")
	if is := srv.Issue(2); !is.Closed || is.Reason != "completed" ||
		!slices.Equal(is.Comments, []string{"The run of 2026-11-05 no longer finds this item, so Hejnal closed the issue."}) {
		t.Errorf("issue 2 after the fix = %+v", is)
	}
	if is := srv.Issue(1); is.Closed || len(is.Comments) != 0 {
		t.Errorf("issue 1 after the fix = %+v", is)
	}

	// A later run finds PHP again: the same issue is reopened.
	if code, _, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run: code %d\n%s", code, errOut)
	}
	h.editRun(testNow.Add(48*time.Hour), func(*state.Snapshot) {})
	code, out, errOut = h.issues()
	if code != exitOK {
		t.Fatalf("back: code %d\n%s%s", code, out, errOut)
	}
	wantOutput(t, "back", out, "reopened #2 · "+php+" · PHP on 127.0.0.1:", " · found again\n", "0 opened, 0 closed, 1 reopened, 1 open already.")
	is := srv.Issue(2)
	if is.Closed || len(is.Comments) != 2 || !strings.HasPrefix(is.Comments[1], "The run of 2026-11-06 finds this item, so Hejnal reopened the issue.") ||
		!strings.Contains(is.Comments[1], "`hejnal accept -item "+php+" -reason \"...\"`") {
		t.Errorf("issue 2 after it came back = %+v", is)
	}
	if n := len(srv.Issues()); n != 2 {
		t.Errorf("%d issues, want the same two", n)
	}

	// Someone closes the issue after the run: the next run checks the fix.
	srv.Requests()
	srv.CloseIssue(2, "completed", testNow.Add(49*time.Hour))
	code, out, _ = h.issues()
	if w := srv.Writes(); code != exitOK || len(w) != 0 || !strings.Contains(out, "left closed #2 · "+php+" · PHP on 127.0.0.1:") ||
		!strings.Contains(out, "closed after the last run; the next run checks it") {
		t.Fatalf("closed after the run: code %d, writes %q\n%s", code, w, out)
	}

	// Someone closes it as not planned, and a run still finds the item: the
	// issue stays closed, with a pointer to the proper record.
	h.editRun(testNow.Add(72*time.Hour), func(*state.Snapshot) {})
	srv.CloseIssue(2, "not_planned", testNow.Add(49*time.Hour))
	code, out, _ = h.issues()
	if w := srv.Writes(); code != exitOK || len(w) != 0 ||
		!strings.Contains(out, "closed as not planned but still found: reopen it, or record the decision with `hejnal accept -item "+php+" -reason \"...\"`") {
		t.Fatalf("not planned: code %d, writes %q\n%s", code, w, out)
	}

	// Closed as done, but a run still finds it: reopened.
	srv.CloseIssue(2, "completed", testNow.Add(49*time.Hour))
	if code, out, _ = h.issues(); code != exitOK || !strings.Contains(out, "reopened #2 · ") || srv.Issue(2).Closed {
		t.Fatalf("closed too early: code %d\n%s", code, out)
	}
}

func TestIssuesAccepted(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	wp := itemIDs(t, h)["WordPress"]
	if code, out, errOut := h.issues(); code != exitOK {
		t.Fatalf("first: code %d\n%s%s", code, out, errOut)
	}

	// An accepted item's issue is closed as not planned, with the reason.
	if code, _, errOut := h.accept("-item", wp, "-reason", "Version 6.8.3 has the fixes, says @anna", "-by", "Anna Nowak"); code != exitOK {
		t.Fatalf("accept: code %d\n%s", code, errOut)
	}
	code, out, errOut := h.issues()
	if code != exitOK {
		t.Fatalf("accepted: code %d\n%s%s", code, out, errOut)
	}
	wantOutput(t, "accepted", out, "closed #1 · "+wp+" · WordPress on 127.0.0.1:", " · accepted until 2027-02-02\n", "0 opened, 1 closed, 0 reopened, 1 open already.")
	is := srv.Issue(1)
	if !is.Closed || is.Reason != "not_planned" || len(is.Comments) != 1 {
		t.Fatalf("issue 1 = %+v", is)
	}
	for _, want := range []string{
		"This item was accepted until 2027-02-02, so Hejnal closed the issue.",
		"- Reason: Version 6.8.3 has the fixes, says @\u2060anna",
		"- Accepted by: Anna Nowak",
	} {
		if !strings.Contains(is.Comments[0], want) {
			t.Errorf("comment is missing %q:\n%s", want, is.Comments[0])
		}
	}

	// While the acceptance holds, the issue stays closed and no new one is
	// opened for the item.
	srv.Requests()
	code, out, _ = h.issues()
	if w := srv.Writes(); code != exitOK || len(w) != 0 || !strings.Contains(out, "0 opened, 0 closed, 0 reopened, 1 open already.") {
		t.Fatalf("still accepted: code %d, writes %q\n%s", code, w, out)
	}

	// When the acceptance has ended and the item is still found, the issue
	// is reopened although it was closed as not planned.
	later := time.Date(2027, 2, 3, 12, 0, 0, 0, time.UTC)
	h.editRun(later.Add(-time.Hour), func(*state.Snapshot) {})
	code, out, errOut = h.runAtTime(later, "issues", "-state", h.state, "-scope", h.scope)
	if code != exitOK {
		t.Fatalf("expired: code %d\n%s%s", code, out, errOut)
	}
	wantOutput(t, "expired", out, "reopened #1 · "+wp+" · WordPress on 127.0.0.1:", " · the acceptance ended on 2027-02-02\n")
	is = srv.Issue(1)
	if is.Closed || len(is.Comments) != 2 ||
		is.Comments[1] != "The acceptance of this item ended on 2027-02-02 and the run of 2027-02-03 still finds it, so Hejnal reopened the issue." {
		t.Errorf("issue 1 after the acceptance ended = %+v", is)
	}
}

func TestIssuesOwners(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	data, err := os.ReadFile(h.scope)
	if err != nil {
		t.Fatal(err)
	}
	owners := `"owners": [{"name": "IT", "github": "@anna", "systems": ["127.0.0.0/8"]}],` + "\n" + `  "hosts"`
	if err := os.WriteFile(h.scope, []byte(strings.Replace(string(data), `"hosts"`, owners, 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	// The owner cannot be assigned in this repository: the issue is opened
	// without an assignee, and says who owns it all the same.
	srv.SetAssignable("piotr")
	code, out, errOut := h.issues("-max-new", "1", "-lang", "pl")
	if code != exitOK {
		t.Fatalf("first: code %d\n%s%s", code, out, errOut)
	}
	wantOutput(t, "first", out, "opened #1 · ", " · IT\n", "1 opened, 0 closed, 0 reopened, 0 open already.",
		"1 item is left for next time: -max-new limits how many issues are opened in one go.")
	if !strings.Contains(errOut, "#1 is not assigned: @anna cannot be assigned issues in acme/infra") {
		t.Errorf("no note about the assignee:\n%s", errOut)
	}
	if is := srv.Issue(1); len(is.Assignees) != 0 || !strings.Contains(is.Body, "- **Priorytet:** krytyczne\n- **Właściciel:** IT\n") {
		t.Errorf("issue 1 = %+v", is)
	}

	// The rest follows the next time, assigned to the owner.
	srv.SetAssignable("anna")
	code, out, errOut = h.issues()
	if code != exitOK || !strings.Contains(out, "1 opened, 0 closed, 0 reopened, 1 open already.") || strings.Contains(out, "left for next time") {
		t.Fatalf("second: code %d\n%s%s", code, out, errOut)
	}
	if is := srv.Issue(2); !slices.Equal(is.Assignees, []string{"anna"}) || !strings.Contains(is.Body, "- **Owner:** IT\n") {
		t.Errorf("issue 2 = %+v", is)
	}
}

func TestIssuesDryRun(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	srv.SetPublic(true)
	php := itemIDs(t, h)["PHP"]
	srv.Add(githubtest.Issue{Title: "Old item", Body: "<!-- hejnal:item:0123abcd -->\nGone since.", Labels: []string{"hejnal"}})
	srv.Add(githubtest.Issue{Title: "PHP", Body: "<!-- hejnal:item:" + php + " -->", Labels: []string{"hejnal"}, Closed: true, Reason: "completed", ClosedAt: testNow.Add(-time.Hour)})
	srv.Add(githubtest.Issue{Title: "Written by a person", Body: "Please look at <!-- hejnal:item:0123abcd -->", Labels: []string{"hejnal"}})

	code, out, errOut := h.issues("-dry-run")
	if w := srv.Writes(); code != exitOK || len(w) != 0 {
		t.Fatalf("dry run: code %d, writes %q\n%s%s", code, w, out, errOut)
	}
	wantOutput(t, "dry run", out,
		"would open · ", " · WordPress on 127.0.0.1:",
		"would reopen #2 · "+php+" · PHP on 127.0.0.1:", " · found again\n",
		"would close #1 · 0123abcd · Old item · no longer found\n",
		"Dry run for acme/infra: would open 1, close 1 and reopen 1; 0 open already. Nothing was changed.")
	if !strings.Contains(errOut, "acme/infra is public") {
		t.Errorf("no note that the repository is public:\n%s", errOut)
	}
}

func TestIssuesMinSeverity(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	h.editRun(testNow, func(snap *state.Snapshot) {
		for i, f := range snap.Findings {
			if f.Technology == "PHP" {
				snap.Findings[i].Severity = match.Low
			}
		}
	})
	code, out, errOut := h.issues("-min-severity", "high")
	if code != exitOK || !strings.Contains(out, "1 opened, 0 closed, 0 reopened, 0 open already.") || !strings.HasPrefix(srv.Issue(1).Title, "WordPress") {
		t.Fatalf("high and up: code %d\n%s%s", code, out, errOut)
	}
	// An item below the floor still counts as found: its issue stays open.
	if code, out, _ = h.issues(); code != exitOK || !strings.Contains(out, "1 opened, 0 closed, 0 reopened, 1 open already.") {
		t.Fatalf("all: code %d\n%s", code, out)
	}
	if code, out, _ = h.issues("-min-severity", "critical"); code != exitOK || !strings.Contains(out, "0 opened, 0 closed, 0 reopened, 2 open already.") {
		t.Fatalf("critical only: code %d\n%s", code, out)
	}
}

func TestIssuesStayOpenWhenNothingAnswered(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	if code, out, errOut := h.issues(); code != exitOK {
		t.Fatalf("first: code %d\n%s%s", code, out, errOut)
	}
	srv.Requests()
	h.editRun(testNow.Add(24*time.Hour), func(snap *state.Snapshot) {
		snap.Services, snap.Findings = 0, nil
	})
	code, out, _ := h.issues()
	if w := srv.Writes(); code != exitOK || len(w) != 0 {
		t.Fatalf("code %d, writes %q\n%s", code, w, out)
	}
	wantOutput(t, "nothing answered", out, "0 opened, 0 closed, 0 reopened, 0 open already.",
		"2 issues are left open: the last run reached no services, so it cannot tell what is fixed.")
}

func TestIssuesRefusals(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	check := func(name, want string, args ...string) {
		t.Helper()
		srv.Requests()
		code, out, errOut := h.issues(args...)
		if w := srv.Writes(); code != exitError || len(w) != 0 || !strings.Contains(errOut, want) {
			t.Errorf("%s: code %d, writes %q, want an error with %q\n%s%s", name, code, w, want, out, errOut)
		}
		if strings.Contains(out+errOut, githubtest.Token) {
			t.Errorf("%s: the output shows the token", name)
		}
	}

	srv.SetPublic(true)
	check("public", "acme/infra is public: its issues would show everyone which of your systems have open items. Use a private repository, or pass -public")
	if code, out, errOut := h.issues("-public", "-max-new", "1"); code != exitOK || len(srv.Issues()) != 1 {
		t.Errorf("-public: code %d\n%s%s", code, out, errOut)
	}
	srv.SetPublic(false)

	srv.SetArchived(true)
	check("archived", "acme/infra is archived")
	srv.SetArchived(false)
	srv.SetIssuesOff(true)
	check("issues off", "issues are turned off in acme/infra")
	srv.SetIssuesOff(false)

	check("bad label", "-label must be one label", "-label", "a,b")
	check("bad severity", "unknown severity", "-min-severity", "urgent")
	check("bad limit", "-max-new must be at least 1", "-max-new", "0")
	check("bad repo", `repository "infra" must look like owner/name`, "-repo", "infra")
	check("other repo", "GitHub answered 404 Not Found to GET /repos/acme/other", "-repo", "acme/other")
	check("no scope", "scope file "+h.dir+"/missing.json not found", "-scope", h.dir+"/missing.json")
	check("no run", "no findings yet", "-state", h.dir+"/empty")

	t.Setenv("GITHUB_TOKEN", "wrong")
	check("bad token", "GitHub answered 401 Unauthorized to GET /repos/acme/infra: Bad credentials. Check the token in HEJNAL_GITHUB_TOKEN or GITHUB_TOKEN")
	// HEJNAL_GITHUB_TOKEN comes first.
	t.Setenv("HEJNAL_GITHUB_TOKEN", githubtest.Token)
	if code, out, errOut := h.issues("-dry-run"); code != exitOK {
		t.Errorf("HEJNAL_GITHUB_TOKEN: code %d\n%s%s", code, out, errOut)
	}
	t.Setenv("HEJNAL_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	check("no token", "no GitHub token: set HEJNAL_GITHUB_TOKEN")
	t.Setenv("GITHUB_TOKEN", githubtest.Token)

	t.Setenv("GITHUB_REPOSITORY", "")
	check("no repo", "name the repository for the issues with -repo owner/name")
	t.Setenv("GITHUB_REPOSITORY", issuesRepo)
	t.Setenv("GITHUB_API_URL", "http://github.example.com/api/v3")
	check("plain http", "must use https, so the token is not sent in the clear")
}

func TestIssuesWithoutScopeFile(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	// The scope file is only needed for owners: without one in the
	// directory, and without -scope, the issues are opened unassigned.
	t.Chdir(t.TempDir())
	code, out, errOut := h.run("issues", "-state", h.state)
	if code != exitOK || len(srv.Issues()) != 2 {
		t.Fatalf("code %d\n%s%s", code, out, errOut)
	}
}

func TestIssuesFailures(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)

	// One change fails: the others still go through, and the exit status
	// says the work is not finished.
	srv.Fail("POST /repos/acme/infra/issues", http.StatusBadGateway)
	code, out, errOut := h.issues()
	if code != exitError || !strings.Contains(out, "1 opened, 0 closed, 0 reopened, 0 open already.") ||
		!strings.Contains(errOut, "GitHub answered 502 Bad Gateway to POST /repos/acme/infra/issues") ||
		!strings.Contains(errOut, "1 change did not go through; run it again to finish") {
		t.Fatalf("one failure: code %d\n%s%s", code, out, errOut)
	}
	// Running it again finishes the work without doing any of it twice.
	if code, out, _ = h.issues(); code != exitOK || !strings.Contains(out, "1 opened, 0 closed, 0 reopened, 1 open already.") || len(srv.Issues()) != 2 {
		t.Fatalf("again: code %d, %d issues\n%s", code, len(srv.Issues()), out)
	}

	// GitHub asks to slow down: nothing further is tried.
	h.editRun(testNow.Add(24*time.Hour), func(snap *state.Snapshot) { snap.Findings = nil })
	srv.Requests()
	srv.Fail("PATCH /repos/acme/infra/issues/1", http.StatusTooManyRequests)
	code, out, errOut = h.issues()
	if w := srv.Writes(); code != exitError || len(w) != 1 || !strings.Contains(errOut, "run it again later") ||
		!strings.Contains(errOut, "2 changes did not go through") {
		t.Fatalf("rate limit: code %d, writes %q\n%s%s", code, w, out, errOut)
	}

	// The comment fails after the issue was closed: the next time does not
	// comment or close again.
	srv.Fail("POST /repos/acme/infra/issues/1/comments", http.StatusBadGateway)
	code, out, _ = h.issues()
	if code != exitError || !strings.Contains(out, "0 opened, 2 closed, 0 reopened, 0 open already.") {
		t.Fatalf("comment failure: code %d\n%s", code, out)
	}
	srv.Requests()
	if code, _, _ = h.issues(); code != exitOK || len(srv.Writes()) != 0 {
		t.Fatalf("after the comment failure: code %d", code)
	}
}

func TestIssuesStopWhenLabelsAreDropped(t *testing.T) {
	h := scanned(t)
	srv := issuesServer(t)
	srv.SetLabelsDropped(true)
	code, out, errOut := h.issues()
	if code != exitError || len(srv.Issues()) != 1 ||
		!strings.Contains(errOut, `GitHub opened #1 without the label "hejnal", so later runs cannot find it.`) {
		t.Fatalf("code %d, %d issues\n%s%s", code, len(srv.Issues()), out, errOut)
	}
}
