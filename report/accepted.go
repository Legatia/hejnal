package report

import (
	"fmt"
	"strings"

	"github.com/Legatia/hejnal/match"
)

// writeAccepted writes the section that lists accepted items: what they are,
// why they were accepted, by whom and until when.
func writeAccepted(b *strings.Builder, tr translator, gs []match.Group) {
	if len(gs) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n%s\n\n", tr("acc.title"), tr("acc.intro"))
	for _, g := range gs {
		parts := []string{mdCode(g.ID()) + " " + mdEscape(groupTitle(tr, g))}
		if a := g.Acceptance(); a != nil {
			parts = append(parts, tr("acc.reason", mdEscape(a.Reason)))
			if a.By != "" {
				parts = append(parts, tr("acc.by", mdEscape(a.By)))
			}
			parts = append(parts, tr("acc.until", mdEscape(a.Until)))
		}
		fmt.Fprintf(b, "- %s\n", strings.Join(parts, " · "))
	}
	b.WriteString("\n")
}

// writeAcceptanceNotes says that part of an item was accepted earlier, so
// only what is new is listed, or that the item's acceptance has expired.
func writeAcceptanceNotes(b *strings.Builder, tr translator, g match.Group, earlier *match.Acceptance) {
	if earlier != nil {
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.accepted"), tr("acc.partly", mdEscape(earlier.Until)))
	}
	if a := g.ExpiredAcceptance(); a != nil {
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.expired"), tr("acc.expired", mdEscape(a.Until)))
	}
}
