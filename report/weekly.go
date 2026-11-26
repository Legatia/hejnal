package report

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// weekWindow is the span a weekly summary covers.
const weekWindow = 7 * 24 * time.Hour

// weekSoonWindow is how far ahead a weekly summary looks for dates that
// fall due.
const weekSoonWindow = 30 * 24 * time.Hour

// Weekly is the weekly summary as plain text for a terminal.
func Weekly(history []*state.Snapshot, cat *kev.Catalog, inv *inventory.Inventory, now time.Time, m Meta) string {
	title, lines := WeeklyLines(history, cat, inv, now, m)
	var b strings.Builder
	b.WriteString(match.CleanNote(title) + "\n")
	for _, l := range lines {
		b.WriteString(match.CleanNote(l) + "\n")
	}
	return b.String()
}

// WeeklyLines is the summary of the last 7 days as a plain title and lines,
// for any channel. It is sent when nothing is new too, so people see that
// Hejnal is checking: how often it ran, which newly exploited flaws it
// checked and whether they touch the organisation, what was fixed and found,
// what is still open and what falls due soon. history are the saved runs, in
// any order; cat, which may be nil, gives the dates flaws were listed; inv
// is the inventory of the last run, which tells what is fixed (see
// FixedItems).
func WeeklyLines(history []*state.Snapshot, cat *kev.Catalog, inv *inventory.Inventory, now time.Time, m Meta) (string, []string) {
	tr := newTranslator(m.Lang)
	start := now.Add(-weekWindow)
	title := tr("wk.title", m.Organization, start.UTC().Format(time.DateOnly), now.UTC().Format(time.DateOnly))

	snaps := slices.Clone(history)
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].GeneratedAt.Before(snaps[j].GeneratedAt) })
	var in []*state.Snapshot
	var before *state.Snapshot
	days := map[string]bool{}
	unreached := 0
	for _, s := range snaps {
		switch {
		case s.GeneratedAt.After(now):
		case s.GeneratedAt.After(start):
			in = append(in, s)
			days[s.GeneratedAt.UTC().Format(time.DateOnly)] = true
			if s.Services == 0 {
				unreached++
			}
		case s.Services > 0:
			before = s
		}
	}
	if len(in) == 0 {
		return title, []string{tr("wk.noruns")}
	}
	// The latest run that reached something describes the organisation now;
	// one that reached nothing, during an outage, would make all look fixed.
	latest := in[len(in)-1]
	for i := len(in) - 1; i >= 0; i-- {
		if in[i].Services > 0 {
			latest = in[i]
			break
		}
	}

	runs := tr("wk.runs", min(len(days), 7), latest.Assets, latest.Services, latest.Technologies)
	if unreached > 0 {
		runs += tr("wk.unreached", unreached)
	}
	lines := []string{runs}
	lines = append(lines, newlyExploited(tr, cat, latest, start, now))

	// Items found and fixed during the week, by comparing the items open at
	// the start of the week (or found during it) with those open now.
	if before == nil {
		lines = append(lines, tr("wk.first"))
	} else {
		known := map[string]bool{}
		for _, f := range match.Active(before.Findings) {
			known[match.GroupKey(f)] = true
		}
		var seenDuring []match.Finding
		seenDuring = append(seenDuring, match.Active(before.Findings)...)
		for _, s := range in {
			if s.Services > 0 {
				seenDuring = append(seenDuring, match.Active(s.Findings)...)
			}
		}
		// The inventory describes the last run, so it can tell what is fixed
		// only if that run reached something.
		if in[len(in)-1] != latest {
			inv = nil
		}
		fixed := len(FixedItems(latest.Findings, seenDuring, inv))
		added := 0
		for _, g := range match.Groups(match.Open(latest.Findings)) {
			if !known[g.Key] {
				added++
			}
		}
		lines = append(lines, tr("wk.fixed", fixed)+" · "+tr("wk.new", added))
	}

	og := match.Groups(match.Open(latest.Findings))
	if len(og) == 0 {
		lines = append(lines, tr("wk.open.none"))
	} else {
		c := match.CountGroups(og)
		lines = append(lines, tr("wk.open", len(og), c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
		if g, since, ok := oldestOpen(snaps, og, now); ok {
			days := int(now.Sub(since).Hours() / 24)
			lines = append(lines, tr("wk.oldest", itemTitle(tr, g), since.UTC().Format(time.DateOnly), days))
		}
	}

	_, acc := match.SplitAccepted(latest.Findings)
	const maxSoon = 3
	for i, e := range comingUp(tr, og, match.Groups(acc), now, weekSoonWindow) {
		if i == maxSoon {
			break
		}
		lines = append(lines, tr("wk.soon", e.date, e.text))
	}
	if len(og) > 0 {
		lines = append(lines, tr("sum.report"))
	}
	return title, lines
}

// newlyExploited says how many flaws CISA and ENISA listed as exploited
// during the week and whether any of them is in the organisation's
// software: affected, or ruled out by the version it shows.
func newlyExploited(tr translator, cat *kev.Catalog, latest *state.Snapshot, start, now time.Time) string {
	if cat == nil {
		return tr("wk.kev.none")
	}
	from, to := start.UTC().Format(time.DateOnly), now.UTC().Format(time.DateOnly)
	listed := map[string]bool{}
	for _, v := range cat.Vulnerabilities {
		d := v.DateAdded
		if v.ENISAEarlier != "" && (d == "" || v.ENISAEarlier < d) {
			d = v.ENISAEarlier
		}
		if d > from && d <= to && v.CVEID != "" {
			listed[v.CVEID] = true
		}
	}
	if len(listed) == 0 {
		return tr("wk.kev.none")
	}
	hit, ruled := map[string]bool{}, map[string]bool{}
	for _, f := range latest.Findings {
		if f.Kind != match.KindKEV || !listed[f.CVE] {
			continue
		}
		if f.RuledOut() {
			ruled[f.CVE] = true
		} else {
			hit[f.CVE] = true
		}
	}
	for c := range hit {
		delete(ruled, c)
	}
	switch {
	case len(hit) > 0:
		return tr("wk.kev.hit", len(listed), len(hit))
	case len(ruled) > 0:
		return tr("wk.kev.ruled", len(listed), len(ruled))
	}
	return tr("wk.kev.clear", len(listed))
}

// oldestOpen returns the open item first seen longest ago, and when.
func oldestOpen(snaps []*state.Snapshot, open []match.Group, now time.Time) (match.Group, time.Time, bool) {
	want := map[string]bool{}
	for _, g := range open {
		want[g.Key] = true
	}
	first := map[string]time.Time{}
	for _, s := range snaps {
		if s.GeneratedAt.After(now) {
			break
		}
		for _, f := range match.Active(s.Findings) {
			k := match.GroupKey(f)
			if _, ok := first[k]; !ok && want[k] {
				first[k] = s.GeneratedAt
			}
		}
	}
	var best match.Group
	var at time.Time
	for _, g := range open {
		if t, ok := first[g.Key]; ok && (at.IsZero() || t.Before(at)) {
			best, at = g, t
		}
	}
	return best, at, !at.IsZero()
}
