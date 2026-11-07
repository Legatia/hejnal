package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Legatia/hejnal/match"
)

// NIS2 writes a draft early warning under NIS2 Article 23, pre-filled with the
// systems and flaws from the latest run that could be involved in an incident.
func NIS2(w io.Writer, fs []match.Finding, m Meta) error {
	tr := newTranslator(m.Lang)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", tr("nis2.title"))
	fmt.Fprintf(&b, "> %s\n\n", tr("nis2.intro", m.GeneratedAt.UTC().Format("2006-01-02"), mdEscape(m.Organization)))

	fmt.Fprintf(&b, "## %s\n\n", tr("nis2.deadlines"))
	for _, k := range []string{"nis2.d24", "nis2.d72", "nis2.d1m", "nis2.pl"} {
		fmt.Fprintf(&b, "- %s\n", tr(k))
	}

	fmt.Fprintf(&b, "\n## %s\n\n", tr("nis2.form"))
	fmt.Fprintf(&b, "- **%s:** %s\n", tr("nis2.entity"), mdEscape(m.Organization))
	for _, k := range []string{"nis2.contact", "nis2.aware", "nis2.what", "nis2.malicious", "nis2.crossborder", "nis2.services"} {
		fmt.Fprintf(&b, "- **%s:** %s\n", tr(k), tr(k+".v"))
	}

	fmt.Fprintf(&b, "\n## %s\n\n", tr("nis2.systems"))
	var rows []match.Finding
	for _, f := range fs {
		if f.Kind == match.KindKEV && !f.RuledOut() && (f.Severity.Rank() >= match.High.Rank() || f.Forensics) {
			rows = append(rows, f)
		}
	}
	if len(rows) == 0 {
		fmt.Fprintf(&b, "%s\n", tr("nis2.nosystems"))
	} else {
		fmt.Fprintf(&b, "%s\n|---|---|---|---|---|\n", tr("nis2.th"))
		for _, f := range rows {
			triage := tr("nis2.no")
			if f.Forensics {
				triage = tr("nis2.yes")
			}
			flaw := mdEscape(f.CVE)
			if f.EUVD != "" {
				flaw += " / " + mdEscape(f.EUVD)
			}
			// The first list to include the flaw, which for a European
			// report is often ENISA's.
			by := match.ListCISA
			if f.ENISAOnly() || f.FirstListed() != f.DateAdded {
				by = match.ListENISA
			}
			listed := mdEscape(f.FirstListed()) + " (" + by + ")"
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", hostPort(f.Host, f.Port), mdEscape(f.Technology), flaw, listed, triage)
		}
	}

	fmt.Fprintf(&b, "\n## %s\n\n", tr("nis2.next"))
	for _, k := range []string{"nis2.c1", "nis2.c2", "nis2.c3", "nis2.c4"} {
		fmt.Fprintf(&b, "- [ ] %s\n", tr(k))
	}
	_, err := io.WriteString(w, b.String())
	return err
}
