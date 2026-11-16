package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Legatia/hejnal/github"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

// cmdIssues keeps one GitHub issue for every item to fix: it opens issues for
// new items, closes the issues of items a run no longer finds or that were
// accepted, and reopens the issues of items that are found again.
func (a *app) cmdIssues(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("issues", "[flags]",
		"Keep a GitHub issue for every item on the fix list, with its priority, owner,\neffort and the command that verifies it. An issue is closed when a later run\nno longer finds its item, closed as not planned when the item is accepted, and\nreopened when the item is found again.\n\nThe token comes from the environment: HEJNAL_GITHUB_TOKEN, or GITHUB_TOKEN as\nGitHub Actions sets it. It needs permission to read and write issues.")
	o.stateFlags(fs)
	o.langFlag(fs)
	fs.StringVar(&o.scope, "scope", "scope.json", "scope file; its owners say whom each issue is assigned to")
	repo := fs.String("repo", "", "repository for the issues, as owner/name (default: $GITHUB_REPOSITORY)")
	label := fs.String("label", "hejnal", "label that marks Hejnal's issues; give each scope its own when several share a repository")
	minSeverity := fs.String("min-severity", "low", "open issues for items of at least this priority: critical, high, medium or low")
	maxNew := fs.Int("max-new", 50, "open at most this many issues in one go; the rest follow next time")
	dryRun := fs.Bool("dry-run", false, "print what would change without changing anything")
	public := fs.Bool("public", false, "allow a public repository, where everyone can read the open items")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	floor, err := match.ParseSeverity(*minSeverity)
	if err != nil {
		return err
	}
	if *maxNew < 1 {
		return fmt.Errorf("-max-new must be at least 1")
	}
	*label = strings.TrimSpace(*label)
	if *label == "" || utf8.RuneCountInString(*label) > 50 || strings.ContainsAny(*label, ",\r\n") {
		return fmt.Errorf("-label must be one label of at most 50 characters, without commas")
	}

	// Owners are optional, so the scope file is too unless it was named.
	var sc *scope.Scope
	named := false
	fs.Visit(func(f *flag.Flag) { named = named || f.Name == "scope" })
	if _, statErr := os.Stat(o.scope); named || !errors.Is(statErr, os.ErrNotExist) {
		if sc, err = a.loadScope(o.scope); err != nil {
			return err
		}
	}

	store := state.Store{Dir: o.stateDir}
	snap, err := store.LoadFindings()
	if err != nil {
		return err
	}
	if err := store.MarkAccepted(snap, a.now()); err != nil {
		return err
	}

	c := &github.Client{
		HTTP:      a.client,
		BaseURL:   os.Getenv("GITHUB_API_URL"),
		Token:     cmp.Or(os.Getenv("HEJNAL_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN")),
		Repo:      cmp.Or(*repo, os.Getenv("GITHUB_REPOSITORY")),
		UserAgent: version.UserAgent(),
		Pause:     a.githubPause,
	}
	switch {
	case c.Repo == "":
		return errors.New("name the repository for the issues with -repo owner/name")
	case c.Token == "":
		return errors.New("no GitHub token: set HEJNAL_GITHUB_TOKEN to a token that may read and write the repository's issues. In GitHub Actions, set GITHUB_TOKEN to ${{ github.token }} and give the job `permissions: issues: write`")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	r, err := c.Repository(ctx)
	if err != nil {
		return err
	}
	switch {
	case r.Archived:
		return fmt.Errorf("%s is archived, so its issues cannot change", c.Repo)
	case !r.HasIssues:
		return fmt.Errorf("issues are turned off in %s: turn them on in the repository's settings", c.Repo)
	case !r.Private && !*public && !*dryRun:
		return fmt.Errorf("%s is public: its issues would show everyone which of your systems have open items. Use a private repository, or pass -public if that is what you want", c.Repo)
	case !r.Private && !*public:
		a.logf("%s is public: its issues would show everyone which of your systems have open items; changing it needs -public", c.Repo)
	}
	existing, err := c.Issues(ctx, *label)
	if err != nil {
		return err
	}

	s := &issueSync{a: a, ctx: ctx, c: c, sc: sc, snap: snap, lang: o.lang, label: *label, dry: *dryRun}
	s.run(itemsOf(snap.Findings), existing, floor, *maxNew)
	s.summary()
	if s.failed > 0 {
		return fmt.Errorf("%s did not go through; run it again to finish", count(s.failed, "change", "changes"))
	}
	return nil
}

// trackedItems are a run's items as the issues need them, by item ID.
type trackedItems struct {
	// open are the items to fix, most urgent first, as the fix list has them.
	open []match.Group
	// earlier is the acceptance of part of an open item.
	earlier map[string]*match.Acceptance
	// accepted are the items that are accepted as a whole.
	accepted map[string]match.Acceptance
	// ruledOut are the items whose flaws the version seen does not have.
	ruledOut map[string]bool
}

// itemsOf sorts a run's findings into items the way the fix list does.
func itemsOf(fs []match.Finding) trackedItems {
	t := trackedItems{
		earlier:  map[string]*match.Acceptance{},
		accepted: map[string]match.Acceptance{},
		ruledOut: map[string]bool{},
	}
	rest, acc := match.SplitAccepted(fs)
	for _, g := range match.Groups(acc) {
		if a := g.Acceptance(); a != nil {
			t.accepted[g.ID()] = *a
		}
	}
	var open []match.Group
	for _, g := range match.Groups(rest) {
		if g.Kind == match.KindKEV && len(match.Active(g.Findings)) == 0 {
			t.ruledOut[g.ID()] = true
			continue
		}
		open = append(open, g)
	}
	for _, sev := range match.Severities {
		for _, g := range open {
			if g.Severity == sev {
				t.open = append(t.open, g)
			}
		}
	}
	for _, g := range t.open {
		id := g.ID()
		if a, ok := t.accepted[id]; ok {
			t.earlier[id] = &a
			delete(t.accepted, id)
		}
		delete(t.ruledOut, id)
	}
	return t
}

// issueSync brings a repository's issues in line with a run.
type issueSync struct {
	a     *app
	ctx   context.Context
	c     *github.Client
	sc    *scope.Scope
	snap  *state.Snapshot
	lang  string
	label string
	dry   bool

	opened, closed, reopened, already int
	// waiting are items left for the next time because of -max-new, and held
	// are issues left open because the run could not tell what is fixed.
	waiting, held int
	failed        int
	// stopped is set when GitHub refuses the token or asks to slow down, so
	// no further change is tried.
	stopped bool
}

func (s *issueSync) run(items trackedItems, existing []github.Issue, floor match.Severity, maxNew int) {
	// The issues of each item, newest first, as GitHub lists them.
	byItem := map[string][]github.Issue{}
	for _, is := range existing {
		if id := report.IssueItem(is.Body); id != "" {
			byItem[id] = append(byItem[id], is)
		}
	}
	isOpen := map[string]bool{}
	for _, g := range items.open {
		id := g.ID()
		isOpen[id] = true
		list := byItem[id]
		switch {
		case slices.ContainsFunc(list, github.Issue.Open):
			s.already++
		case len(list) > 0:
			s.reopen(list[0], g)
		case g.Severity.Rank() < floor.Rank():
		case s.opened >= maxNew:
			s.waiting++
		default:
			s.open(g, items.earlier[id])
		}
	}
	// Oldest first, so the output follows the issue numbers.
	for _, is := range slices.Backward(existing) {
		id := report.IssueItem(is.Body)
		if id == "" || isOpen[id] || !is.Open() {
			continue
		}
		title := shortTitle(is.Title)
		if acc, ok := items.accepted[id]; ok {
			s.close(is, id, title, github.NotPlanned, "accepted until "+acc.Until, report.IssueAccepted(s.lang, acc))
			continue
		}
		if s.snap.Services == 0 {
			// A run that reached nothing would make every item look fixed.
			s.held++
			continue
		}
		note := "no longer found"
		if items.ruledOut[id] {
			note = "the version seen is not affected"
		}
		s.close(is, id, title, github.Completed, note, report.IssueGone(s.lang, s.snap.GeneratedAt, items.ruledOut[id]))
	}
}

// open opens the issue for an item.
func (s *issueSync) open(g match.Group, earlier *match.Acceptance) {
	var owner *scope.Owner
	if s.sc != nil {
		owner = s.sc.OwnerOf(g.Host)
	}
	opts := report.IssueOptions{Lang: s.lang, Run: s.snap.GeneratedAt, Earlier: earlier}
	who := ""
	n := github.NewIssue{Labels: []string{s.label}}
	if owner != nil {
		opts.Owner = owner.Label()
		who = " · " + owner.Label()
		if owner.GitHub != "" {
			n.Assignees = []string{owner.GitHub}
		}
	}
	is := report.IssueFor(g, opts)
	n.Title, n.Body = is.Title, is.Body
	line := fmt.Sprintf("%s · %s%s", is.Item, shortTitle(is.Title), who)
	if s.dry {
		s.opened++
		fmt.Fprintf(s.a.stdout, "would open · %s\n", line)
		return
	}
	if s.stopped {
		s.failed++
		return
	}
	created, unassigned, err := s.c.Create(s.ctx, n)
	if err != nil {
		s.fail(err)
		return
	}
	s.opened++
	fmt.Fprintf(s.a.stdout, "opened #%d · %s\n", created.Number, line)
	if unassigned {
		s.a.logf("#%d is not assigned: @%s cannot be assigned issues in %s", created.Number, owner.GitHub, s.c.Repo)
	}
	if !created.HasLabel(s.label) {
		// Without the label the next run would not find the issue and
		// would open it again, so stop here.
		s.a.logf("GitHub opened #%d without the label %q, so later runs cannot find it. The token's account needs triage access to %s to label issues. Add the label to #%d by hand, or close it", created.Number, s.label, s.c.Repo, created.Number)
		s.failed++
		s.stopped = true
	}
}

// reopen opens the closed issue of an item that is still found, unless
// someone closed it on purpose.
func (s *issueSync) reopen(is github.Issue, g match.Group) {
	id := g.ID()
	line := fmt.Sprintf("#%d · %s · %s", is.Number, id, shortTitle(report.ItemTitle(g, s.lang)))
	expired := g.ExpiredAcceptance()
	switch {
	case is.ClosedAt != nil && is.ClosedAt.After(s.snap.GeneratedAt):
		// Closed since the run: the next run says whether the fix worked.
		fmt.Fprintf(s.a.stdout, "left closed %s · closed after the last run; the next run checks it\n", line)
		return
	case is.StateReason == github.NotPlanned && expired == nil:
		fmt.Fprintf(s.a.stdout, "left closed %s · closed as not planned but still found: reopen it, or record the decision with `hejnal accept -item %s -reason \"...\"`\n", line, id)
		return
	}
	note := "found again"
	if expired != nil {
		note = "the acceptance ended on " + expired.Until
	}
	if s.dry {
		s.reopened++
		fmt.Fprintf(s.a.stdout, "would reopen %s · %s\n", line, note)
		return
	}
	if s.stopped {
		s.failed++
		return
	}
	// The state changes first: if the comment then fails, the next run
	// does not comment a second time.
	if err := s.c.Reopen(s.ctx, is.Number); err != nil {
		s.fail(err)
		return
	}
	s.reopened++
	fmt.Fprintf(s.a.stdout, "reopened %s · %s\n", line, note)
	if err := s.c.Comment(s.ctx, is.Number, report.IssueFound(s.lang, id, s.snap.GeneratedAt, expired)); err != nil {
		s.fail(err)
	}
}

// close closes an issue with a comment that says why.
func (s *issueSync) close(is github.Issue, id, title, reason, note, comment string) {
	line := fmt.Sprintf("#%d · %s · %s · %s", is.Number, id, title, note)
	if s.dry {
		s.closed++
		fmt.Fprintf(s.a.stdout, "would close %s\n", line)
		return
	}
	if s.stopped {
		s.failed++
		return
	}
	if err := s.c.Close(s.ctx, is.Number, reason); err != nil {
		s.fail(err)
		return
	}
	s.closed++
	fmt.Fprintf(s.a.stdout, "closed %s\n", line)
	if err := s.c.Comment(s.ctx, is.Number, comment); err != nil {
		s.fail(err)
	}
}

// fail records a change that did not go through. The other changes are still
// tried, unless GitHub refused the token or asked to slow down.
func (s *issueSync) fail(err error) {
	s.failed++
	s.a.logf("%v", err)
	var ge *github.Error
	switch {
	case errors.As(err, &ge):
		s.stopped = s.stopped || ge.RateLimited || ge.Status == http.StatusUnauthorized || ge.Status == http.StatusForbidden
	case s.ctx.Err() != nil:
		s.stopped = true
	}
}

func (s *issueSync) summary() {
	w := s.a.stdout
	if s.dry {
		fmt.Fprintf(w, "Dry run for %s: would open %d, close %d and reopen %d; %d open already. Nothing was changed.\n",
			s.c.Repo, s.opened, s.closed, s.reopened, s.already)
	} else {
		fmt.Fprintf(w, "Issues in %s: %d opened, %d closed, %d reopened, %d open already.\n",
			s.c.Repo, s.opened, s.closed, s.reopened, s.already)
	}
	if s.waiting > 0 {
		fmt.Fprintf(w, "%s left for next time: -max-new limits how many issues are opened in one go.\n", count(s.waiting, "item is", "items are"))
	}
	if s.held > 0 {
		fmt.Fprintf(w, "%s left open: the last run reached no services, so it cannot tell what is fixed.\n", count(s.held, "issue is", "issues are"))
	}
}

// shortTitle makes a title safe and short enough for one line of output.
func shortTitle(s string) string {
	s = match.CleanNote(s)
	const limit = 100
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit-1]) + "…"
	}
	return s
}
