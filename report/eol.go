package report

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Legatia/hejnal/match"
)

// eolText names an item about a release's end of support, says why it
// matters and what to do: in Markdown for the fix list, or as plain text.
func eolText(tr translator, f match.Finding, where string, md bool) (title, why, todo string) {
	esc, code := func(s string) string { return s }, func(s string) string { return s }
	if md {
		esc, code = mdEscape, mdCode
	}
	tech, rel := esc(f.Technology), esc(f.Release)
	switch {
	case !f.SupportEnded:
		title, why = tr("eols.title", tech, rel, where), tr("eols.why", tech, rel, f.SupportEnds)
	case f.SupportEnds == "":
		title, why = tr("eolx.title", tech, rel, where), tr("eolx.why.nodate", tech, rel)
	default:
		title, why = tr("eolx.title", tech, rel, where), tr("eolx.why", tech, rel, f.SupportEnds)
	}
	switch len(f.UpgradeTo) {
	case 0:
		todo = tr("eol.todo.none")
	case 1:
		todo = tr("eol.todo.one", code(f.UpgradeTo[0]))
	default:
		todo = tr("eol.todo.two", code(f.UpgradeTo[0]), code(f.UpgradeTo[1]))
	}
	return title, why, todo
}

// comingUpWindow is how far ahead the fix list looks for known dates.
const comingUpWindow = 90 * 24 * time.Hour

// writeComingUp lists what falls due on a known day within the window:
// releases whose support ends, certificates that expire and acceptances
// that end, soonest first, so the work can be planned before the day.
func writeComingUp(b *strings.Builder, tr translator, open, accepted []match.Group, now time.Time) {
	type event struct{ date, text, id string }
	var events []event
	today := now.UTC().Format(time.DateOnly)
	until := now.Add(comingUpWindow).UTC().Format(time.DateOnly)
	add := func(date, text, id string) {
		if date >= today && date <= until {
			events = append(events, event{date, text, id})
		}
	}
	for _, g := range open {
		f := g.Findings[0]
		switch g.Kind {
		case match.KindEOL:
			if !f.SupportEnded {
				add(f.SupportEnds, itemTitle(tr, g), g.ID())
			}
		case match.KindTLSExpiring:
			if f.Expires != nil {
				add(f.Expires.UTC().Format(time.DateOnly), itemTitle(tr, g), g.ID())
			}
		}
	}
	for _, g := range accepted {
		if a := g.Acceptance(); a != nil {
			add(a.Until, tr("soon.acc", groupTitle(tr, g)), g.ID())
		}
	}
	if len(events) == 0 {
		return
	}
	slices.SortStableFunc(events, func(x, y event) int { return strings.Compare(x.date, y.date) })
	fmt.Fprintf(b, "## %s\n\n%s\n\n", tr("soon.title"), tr("soon.intro"))
	for _, e := range events {
		fmt.Fprintf(b, "- **%s** · %s · %s\n", e.date, mdEscape(e.text), mdCode(e.id))
	}
	b.WriteString("\n")
}
