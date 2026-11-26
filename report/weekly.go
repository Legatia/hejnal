package report

import (
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// weekWindow is the span a weekly summary covers when it has no earlier
// summary to follow on from.
const weekWindow = 7 * 24 * time.Hour

// weekSoonWindow is how far ahead a weekly summary looks for dates that
// fall due.
const weekSoonWindow = 30 * 24 * time.Hour

// Weekly is the weekly summary as plain text for a terminal.
func Weekly(history []*state.Snapshot, cat *kev.Catalog, inv *inventory.Inventory, from, now time.Time, m Meta) string {
	title, lines := WeeklyLines(history, cat, inv, from, now, m)
	var b strings.Builder
	b.WriteString(match.CleanNote(title) + "\n")
	for _, l := range lines {
		b.WriteString(match.CleanNote(l) + "\n")
	}
	return b.String()
}

// WeeklyLines is the summary of the time since from as a plain title and
// lines, for any channel. It is sent when nothing is new too, so people see
// that Hejnal is checking: how often it ran, which newly exploited flaws it
// checked and whether they touch the organisation, what was fixed and found,
// what is still open and what falls due soon.
//
// from is when the last summary was sent, so summaries neither skip nor
// repeat a day; the zero time, or one more than two weeks back, means the
// last 7 days. history are the saved runs, in any order; cat, which may be
// nil, gives the dates flaws were listed; inv is the inventory of the last
// run, which tells what is fixed (see FixedItems).
func WeeklyLines(history []*state.Snapshot, cat *kev.Catalog, inv *inventory.Inventory, from, now time.Time, m Meta) (string, []string) {
	tr := newTranslator(m.Lang)
	start := from
	if start.IsZero() || !start.Before(now) || now.Sub(start) > 2*weekWindow {
		start = now.Add(-weekWindow)
	}
	span := int(math.Ceil(now.Sub(start).Hours() / 24))
	title := tr("wk.title", m.Organization, start.UTC().Format(time.DateOnly), now.UTC().Format(time.DateOnly))

	snaps := slices.Clone(history)
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].GeneratedAt.Before(snaps[j].GeneratedAt) })
	var in []*state.Snapshot
	// latest is the last run that reached something, at any time: a run that
	// reached nothing, during an outage, would make everything look fixed.
	// before is the last such run before the period.
	var latest, before *state.Snapshot
	days := map[string]bool{}
	unreached := 0
	for _, s := range snaps {
		if s.GeneratedAt.After(now) {
			break
		}
		if s.Services > 0 {
			latest = s
		}
		if !s.GeneratedAt.After(start) {
			if s.Services > 0 {
				before = s
			}
			continue
		}
		in = append(in, s)
		days[s.GeneratedAt.UTC().Format(time.DateOnly)] = true
		if s.Services == 0 {
			unreached++
		}
	}
	if len(in) == 0 {
		return title, []string{tr("wk.noruns", span)}
	}
	runs := tr("wk.runs", min(len(days), span), span)
	if latest != nil {
		runs += tr("wk.size", latest.Assets, latest.Services, latest.Technologies)
	}
	if unreached > 0 {
		runs += tr("wk.unreached", unreached)
	}
	lines := []string{runs}
	if latest == nil {
		return title, append(lines, tr("wk.noreach"))
	}
	stale := !latest.GeneratedAt.After(start)
	if stale {
		// No run of the period reached anything: say what the last one that
		// did found, and that it is older.
		lines = append(lines, tr("wk.stale", latest.GeneratedAt.UTC().Format(time.DateOnly)))
	}
	if line := newlyExploited(tr, cat, latest, start, now, stale); line != "" {
		lines = append(lines, line)
	}

	// Items found and fixed during the period, by comparing the items open
	// at its start, or found during it, with those open now.
	switch {
	case stale:
	case before == nil:
		lines = append(lines, tr("wk.first"))
	default:
		known := map[string]bool{}
		for _, f := range match.Active(before.Findings) {
			known[match.GroupKey(f)] = true
		}
		seenDuring := match.Active(before.Findings)
		for _, s := range in {
			if s.Services > 0 {
				seenDuring = append(seenDuring, match.Active(s.Findings)...)
			}
		}
		// The inventory describes the last run, so it can tell what is fixed
		// only if that run is the one that reached something.
		if in[len(in)-1] != latest {
			inv = nil
		}
		fixed := len(FixedItems(latest, seenDuring, inv))
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
// during the period and whether any of them is in the organisation's
// software: affected, or ruled out by the version it shows. Only flaws
// listed by the day of the last run that reached something were checked.
// Without the catalog it says nothing, since it cannot tell.
func newlyExploited(tr translator, cat *kev.Catalog, latest *state.Snapshot, start, now time.Time, stale bool) string {
	if cat == nil {
		return ""
	}
	from := start.UTC().Format(time.DateOnly)
	to := now.UTC().Format(time.DateOnly)
	if checked := latest.GeneratedAt.UTC().Format(time.DateOnly); !stale && checked < to {
		to = checked
	}
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
	switch {
	case len(listed) == 0:
		return tr("wk.kev.none")
	case stale:
		return tr("wk.kev.unchecked", len(listed))
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
