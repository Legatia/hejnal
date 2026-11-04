package report

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

var monthNames = map[string][]string{
	"en": {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"},
	"pl": {"styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec", "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień"},
}

func monthName(lang string, t time.Time) string {
	names, ok := monthNames[lang]
	if !ok {
		names = monthNames["en"]
	}
	return fmt.Sprintf("%s %d", names[t.Month()-1], t.Year())
}

// Monthly writes a month's exposure report from the run history: what the
// organisation exposed, what was found and fixed during the month, how long
// fixes took, and what is still open.
func Monthly(w io.Writer, history []*state.Snapshot, month time.Time, m Meta) error {
	tr := newTranslator(m.Lang)
	start := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	snaps := slices.Clone(history)
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].GeneratedAt.Before(snaps[j].GeneratedAt) })
	// A run that reached no services, during an outage or when the scanner
	// was blocked, would make everything look fixed. Leave such runs out
	// unless no run of the month reached anything.
	unreachable := 0
	reached := slices.ContainsFunc(snaps, func(s *state.Snapshot) bool {
		return s.Services > 0 && !s.GeneratedAt.Before(start) && s.GeneratedAt.Before(end)
	})
	if reached {
		kept := snaps[:0]
		for _, s := range snaps {
			if s.Services > 0 {
				kept = append(kept, s)
			} else if !s.GeneratedAt.Before(start) && s.GeneratedAt.Before(end) {
				unreachable++
			}
		}
		snaps = kept
	}

	var before *state.Snapshot
	var in []*state.Snapshot
	for _, s := range snaps {
		switch {
		case s.GeneratedAt.Before(start):
			before = s
		case s.GeneratedAt.Before(end):
			in = append(in, s)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", tr("mon.title", monthName(m.Lang, start)), mdEscape(m.Organization))
	if len(in) == 0 {
		fmt.Fprintf(&b, "%s\n", tr("mon.noruns"))
		_, err := io.WriteString(w, b.String())
		return err
	}
	first, last := in[0], in[len(in)-1]
	if before != nil {
		first = before
	}

	// When each finding was first and last seen, up to the end of the month.
	firstSeen := map[string]time.Time{}
	lastSeen := map[string]time.Time{}
	lastFinding := map[string]match.Finding{}
	for _, s := range snaps {
		if !s.GeneratedAt.Before(end) {
			break
		}
		for _, f := range match.Active(s.Findings) {
			if _, ok := firstSeen[f.Key]; !ok {
				firstSeen[f.Key] = s.GeneratedAt
			}
			lastSeen[f.Key] = s.GeneratedAt
			lastFinding[f.Key] = f
		}
	}
	open := match.Active(last.Findings)
	openKeys := map[string]bool{}
	for _, f := range open {
		openKeys[f.Key] = true
	}
	// Candidates for "fixed": open at the start of the month or seen during it.
	candidates := map[string]bool{}
	if before != nil {
		for _, f := range match.Active(before.Findings) {
			candidates[f.Key] = true
		}
	}
	for _, s := range in {
		for _, f := range match.Active(s.Findings) {
			candidates[f.Key] = true
		}
	}
	var newFs, fixedFs []match.Finding
	var fixDays []float64
	for key := range candidates {
		f := lastFinding[key]
		if fs := firstSeen[key]; !fs.Before(start) && fs.Before(end) {
			newFs = append(newFs, f)
		}
		if !openKeys[key] {
			fixedFs = append(fixedFs, f)
			// Fixed by the first run after it was last seen.
			for _, s := range in {
				if s.GeneratedAt.After(lastSeen[key]) {
					fixDays = append(fixDays, s.GeneratedAt.Sub(firstSeen[key]).Hours()/24)
					break
				}
			}
		}
	}

	fmt.Fprintf(&b, "%s\n\n", tr("mon.period", start.Format("2006-01-02"), end.AddDate(0, 0, -1).Format("2006-01-02"), len(in)))
	if unreachable > 0 {
		fmt.Fprintf(&b, "> %s\n\n", tr("mon.unreachable", unreachable))
	}

	fmt.Fprintf(&b, "## %s\n\n", tr("mon.exposure"))
	fmt.Fprintf(&b, "| | %s | %s |\n|---|---|---|\n", tr("mon.start"), tr("mon.end"))
	fmt.Fprintf(&b, "| %s | %d | %d |\n", tr("mon.hosts"), first.Assets, last.Assets)
	fmt.Fprintf(&b, "| %s | %d | %d |\n", tr("mon.services"), first.Services, last.Services)
	fmt.Fprintf(&b, "| %s | %d | %d |\n\n", tr("mon.products"), first.Technologies, last.Technologies)

	og := match.Groups(open)
	c := match.CountGroups(og)
	fmt.Fprintf(&b, "## %s\n\n", tr("mon.summary"))
	fmt.Fprintf(&b, "- %s\n", tr("mon.new", len(match.Groups(newFs))))
	fmt.Fprintf(&b, "- %s\n", tr("mon.fixed", len(match.Groups(fixedFs))))
	if len(fixDays) > 0 {
		fmt.Fprintf(&b, "- %s\n", tr("mon.median", median(fixDays)))
	}
	fmt.Fprintf(&b, "- %s\n\n", tr("mon.open", len(og), c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))

	writeList := func(heading string, fs []match.Finding, withSince bool) {
		gs := match.Groups(fs)
		if len(gs) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n", heading)
		for i, g := range gs {
			if i == 15 {
				fmt.Fprintf(&b, "- %s\n", tr("sum.more", len(gs)-15))
				break
			}
			line := fmt.Sprintf("- [%s] %s", tr("sev.short."+string(g.Severity)), mdEscape(groupTitle(tr, g)))
			if withSince {
				since := firstSeen[g.Findings[0].Key]
				for _, f := range g.Findings {
					if t := firstSeen[f.Key]; t.Before(since) {
						since = t
					}
				}
				line += " · " + tr("mon.since", since.Format("2006-01-02"))
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}
	writeList(tr("mon.newlist"), newFs, false)
	writeList(tr("mon.fixedlist"), fixedFs, false)
	writeList(tr("mon.openlist"), open, true)

	fmt.Fprintf(&b, "---\n\n%s\n", tr("mon.footer"))
	_, err := io.WriteString(w, b.String())
	return err
}

func median(v []float64) string {
	s := slices.Clone(v)
	slices.Sort(s)
	mid := s[len(s)/2]
	if len(s)%2 == 0 {
		mid = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return fmt.Sprintf("%.1f", mid)
}
