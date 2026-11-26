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
	w := weekOf(history, cat, inv, from, now)
	title := tr("wk.title", m.Organization, w.start.UTC().Format(time.DateOnly), now.UTC().Format(time.DateOnly))
	if len(w.in) == 0 {
		return title, []string{tr("wk.noruns", w.span)}
	}
	runs := tr("wk.runs", w.days, w.span)
	if w.latest != nil {
		runs += tr("wk.size", w.latest.Assets, w.latest.Services, w.latest.Technologies)
	}
	if w.unreached > 0 {
		runs += tr("wk.unreached", w.unreached)
	}
	lines := []string{runs}
	if w.latest == nil {
		return title, append(lines, tr("wk.noreach"))
	}
	if w.stale {
		// No run of the period reached anything: say what the last one that
		// did found, and that it is older.
		lines = append(lines, tr("wk.stale", w.latest.GeneratedAt.UTC().Format(time.DateOnly)))
	}
	if line := w.kev.line(tr); line != "" {
		lines = append(lines, line)
	}
	switch {
	case w.stale:
	case w.before == nil:
		lines = append(lines, tr("wk.first"))
	default:
		lines = append(lines, tr("wk.fixed", len(w.fixed))+" · "+tr("wk.new", w.added))
	}

	if len(w.open) == 0 {
		lines = append(lines, tr("wk.open.none"))
	} else {
		c := match.CountGroups(w.open)
		lines = append(lines, tr("wk.open", len(w.open), c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
		if g, since, ok := oldestOpen(w.snaps, w.open, now); ok {
			days := int(now.Sub(since).Hours() / 24)
			lines = append(lines, tr("wk.oldest", itemTitle(tr, g), since.UTC().Format(time.DateOnly), days))
		}
	}

	_, acc := match.SplitAccepted(w.latest.Findings)
	const maxSoon = 3
	for i, e := range comingUp(tr, w.open, match.Groups(acc), now, weekSoonWindow) {
		if i == maxSoon {
			break
		}
		lines = append(lines, tr("wk.soon", e.date, e.text))
	}
	if len(w.open) > 0 {
		lines = append(lines, tr("sum.report"))
	}
	return title, lines
}

// WeeklyStats returns the numbers of the summary WeeklyLines writes for the
// same arguments, to keep and compare weeks.
func WeeklyStats(history []*state.Snapshot, cat *kev.Catalog, inv *inventory.Inventory, from, now time.Time) state.Week {
	w := weekOf(history, cat, inv, from, now)
	out := state.Week{
		Start: w.start.UTC(), End: now.UTC(), Days: w.span, DaysChecked: w.days,
		Reached: w.latest != nil && !w.stale, Compared: w.compared,
		CatalogRead: w.kev.known, Listed: w.kev.checked, Affected: w.kev.hit, Unchecked: w.kev.unchecked,
	}
	if len(w.in) == 0 {
		return out
	}
	if w.compared {
		out.Fixed, out.New = len(w.fixed), w.added
		first := firstSeen(w.snaps, w.fixed, now)
		for _, g := range w.fixed {
			if t, ok := first[g.Key]; ok {
				out.FixDays = append(out.FixDays, max(0, int(w.latest.GeneratedAt.Sub(t).Hours()/24)))
			}
		}
	}
	if w.latest != nil {
		c := match.CountGroups(w.open)
		out.Open = len(w.open)
		out.Critical, out.High, out.Medium, out.Low = c[match.Critical], c[match.High], c[match.Medium], c[match.Low]
	}
	return out
}

// week is what a weekly summary is made from.
type week struct {
	start time.Time
	// span is the length of the period in days, days the days with a run.
	span, days int
	snaps      []*state.Snapshot // all runs up to now, oldest first
	in         []*state.Snapshot // the runs of the period
	// latest is the last run that reached something, at any time: a run
	// that reached nothing, during an outage, would make everything look
	// fixed. before is the last such run before the period.
	latest, before *state.Snapshot
	unreached      int
	// stale is set when no run of the period reached anything.
	stale bool
	kev   kevCount
	// compared is set when fixed and added were counted.
	compared bool
	fixed    []match.Group
	added    int
	open     []match.Group
}

func weekOf(history []*state.Snapshot, cat *kev.Catalog, inv *inventory.Inventory, from, now time.Time) week {
	w := week{start: from}
	if w.start.IsZero() || !w.start.Before(now) || now.Sub(w.start) > 2*weekWindow {
		w.start = now.Add(-weekWindow)
	}
	// Rounded, so a run a few seconds later than last week's does not add a
	// day.
	w.span = max(1, int(math.Round(now.Sub(w.start).Hours()/24)))

	snaps := slices.Clone(history)
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].GeneratedAt.Before(snaps[j].GeneratedAt) })
	days := map[string]bool{}
	for _, s := range snaps {
		if s.GeneratedAt.After(now) {
			break
		}
		w.snaps = append(w.snaps, s)
		if s.Services > 0 {
			w.latest = s
		}
		if !s.GeneratedAt.After(w.start) {
			if s.Services > 0 {
				w.before = s
			}
			continue
		}
		w.in = append(w.in, s)
		days[s.GeneratedAt.UTC().Format(time.DateOnly)] = true
		if s.Services == 0 {
			w.unreached++
		}
	}
	w.days = min(len(days), w.span)
	if len(w.in) == 0 || w.latest == nil {
		return w
	}
	w.stale = !w.latest.GeneratedAt.After(w.start)
	w.kev = countNewlyExploited(cat, w.latest, w.start, now, w.stale)
	w.open = match.Groups(match.Open(w.latest.Findings))
	if w.stale || w.before == nil {
		return w
	}

	// Items found and fixed during the period, by comparing the items open
	// at its start, or found during it, with those open now.
	w.compared = true
	known := map[string]bool{}
	for _, f := range match.Active(w.before.Findings) {
		known[match.GroupKey(f)] = true
	}
	seenDuring := match.Active(w.before.Findings)
	for _, s := range w.in {
		if s.Services > 0 {
			seenDuring = append(seenDuring, match.Active(s.Findings)...)
		}
	}
	// The inventory describes the last run, so it can tell what is fixed
	// only if that run is the one that reached something.
	if w.in[len(w.in)-1] != w.latest {
		inv = nil
	}
	w.fixed = FixedItems(w.latest, seenDuring, inv)
	for _, g := range w.open {
		if !known[g.Key] {
			w.added++
		}
	}
	return w
}

// kevCount counts the flaws CISA and ENISA listed as exploited during a
// period: checked against the last run that reached something, of them hit
// (in the organisation's software) and ruled (in it, but not the affected
// versions), and unchecked (listed after that run). known is false without
// the catalog.
type kevCount struct {
	known                          bool
	checked, hit, ruled, unchecked int
}

// countNewlyExploited counts the flaws listed from the day a period starts
// up to the day before it ends, so each summary counts each flaw once, also
// one listed on the day of a summary after it was sent. Flaws listed on or
// after the day of the last run that reached something may not have been in
// the catalog it used, so they are counted as not checked yet.
func countNewlyExploited(cat *kev.Catalog, latest *state.Snapshot, start, now time.Time, stale bool) kevCount {
	if cat == nil {
		return kevCount{}
	}
	from := start.UTC().Format(time.DateOnly)
	to := now.UTC().Format(time.DateOnly)
	checkedTo := latest.GeneratedAt.UTC().Format(time.DateOnly)
	if stale {
		checkedTo = ""
	}
	checked, unchecked := map[string]bool{}, map[string]bool{}
	for _, v := range cat.Vulnerabilities {
		d := v.DateAdded
		if v.ENISAEarlier != "" && (d == "" || v.ENISAEarlier < d) {
			d = v.ENISAEarlier
		}
		if v.CVEID == "" || d < from || d >= to {
			continue
		}
		if d < checkedTo {
			checked[v.CVEID] = true
		} else {
			unchecked[v.CVEID] = true
		}
	}
	hit, ruled := map[string]bool{}, map[string]bool{}
	for _, f := range latest.Findings {
		if f.Kind != match.KindKEV || !checked[f.CVE] {
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
	return kevCount{known: true, checked: len(checked), hit: len(hit), ruled: len(ruled), unchecked: len(unchecked)}
}

// line says how many flaws were newly listed as exploited and whether any
// of them is in the organisation's software. Without the catalog it says
// nothing, since it cannot tell.
func (k kevCount) line(tr translator) string {
	if !k.known {
		return ""
	}
	later := ""
	if k.unchecked > 0 {
		later = tr("wk.kev.unchecked", k.unchecked)
	}
	if k.checked == 0 {
		if later != "" {
			return later
		}
		return tr("wk.kev.none")
	}
	var line string
	switch {
	case k.hit > 0:
		line = tr("wk.kev.hit", k.checked, k.hit)
	case k.ruled > 0:
		line = tr("wk.kev.ruled", k.checked, k.ruled)
	default:
		line = tr("wk.kev.clear", k.checked)
	}
	if later != "" {
		line += " " + later
	}
	return line
}

// oldestOpen returns the open item first seen longest ago, and when.
func oldestOpen(snaps []*state.Snapshot, open []match.Group, now time.Time) (match.Group, time.Time, bool) {
	first := firstSeen(snaps, open, now)
	var best match.Group
	var at time.Time
	for _, g := range open {
		if t, ok := first[g.Key]; ok && (at.IsZero() || t.Before(at)) {
			best, at = g, t
		}
	}
	return best, at, !at.IsZero()
}

// firstSeen returns when each of the items was first found, up to now.
func firstSeen(snaps []*state.Snapshot, items []match.Group, now time.Time) map[string]time.Time {
	want := map[string]bool{}
	for _, g := range items {
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
	return first
}
