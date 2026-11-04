// Package report writes Hejnal's findings for people: a prioritised fix list,
// a short summary for chat, and a NIS2 early-warning draft. Reports are
// Markdown, in English or Polish.
package report

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/match"
)

// Meta describes the run a report is about.
type Meta struct {
	Organization string
	GeneratedAt  time.Time
	Lang         string
	KEVVersion   string
	EPSSDate     string
	Assets       int
	Services     int
	Technologies int
}

// maxFlaws is how many flaws a fix-list item lists before summarising.
const maxFlaws = 5

// maxLinks is how many advisory links a fix-list item shows.
const maxLinks = 4

// FixList writes the prioritised list of things to fix.
func FixList(w io.Writer, fs []match.Finding, m Meta) error {
	tr := newTranslator(m.Lang)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", tr("fix.title"), mdEscape(m.Organization))
	fmt.Fprintf(&b, "%s\n\n", tr("fix.meta", m.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"), m.Assets, m.Services, m.Technologies))
	if m.KEVVersion != "" {
		b.WriteString(tr("fix.feeds", m.KEVVersion))
		if m.EPSSDate != "" {
			b.WriteString(tr("fix.feeds.epss", m.EPSSDate))
		}
		b.WriteString(".\n\n")
	}

	// Items whose flaws the version check all ruled out go to the end.
	var groups, fixed []match.Group
	for _, g := range match.Groups(fs) {
		if g.Kind == match.KindKEV && len(match.Active(g.Findings)) == 0 {
			fixed = append(fixed, g)
		} else {
			groups = append(groups, g)
		}
	}
	c := match.CountGroups(groups)
	fmt.Fprintf(&b, "**%s**\n\n", tr("fix.summary", c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	if len(groups) == 0 {
		if m.Services == 0 {
			fmt.Fprintf(&b, "%s\n\n", tr("fix.empty"))
		} else {
			fmt.Fprintf(&b, "%s\n\n", tr("fix.none"))
		}
	}

	n := 0
	for _, sev := range match.Severities {
		first := true
		for _, g := range groups {
			if g.Severity != sev {
				continue
			}
			if first {
				fmt.Fprintf(&b, "## %s\n\n", tr("sev."+string(sev)))
				first = false
			}
			n++
			writeGroup(&b, tr, n, g)
		}
	}
	if len(fixed) > 0 {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", tr("fix.ruledout.title"), tr("fix.ruledout.intro"))
		for _, g := range fixed {
			fmt.Fprintf(&b, "- %s (%s): %s\n", tr("kev.title", mdEscape(g.Technology), hostPort(g.Host, g.Port)),
				tr("label.version", mdCode(g.Version)), strings.Join(cveList(g.Findings), ", "))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "---\n\n%s\n", tr("fix.footer"))
	_, err := io.WriteString(w, b.String())
	return err
}

func writeGroup(b *strings.Builder, tr translator, n int, g match.Group) {
	where := hostPort(g.Host, g.Port)
	switch g.Kind {
	case match.KindKEV:
		active := match.Active(g.Findings)
		var ruledOut []match.Finding
		confirmed, packaged := false, false
		for _, f := range g.Findings {
			switch {
			case f.RuledOut():
				ruledOut = append(ruledOut, f)
			case f.Confidence == match.ConfidenceVersion:
				confirmed = true
			}
			packaged = packaged || f.Packaged
		}
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("kev.title", mdEscape(g.Technology), where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("kev.why", len(active), newest(active)))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("kev.todo"))
		if g.Forensics() {
			fmt.Fprintf(b, "- **%s:** %s\n", tr("label.compromise"), tr("kev.forensic"))
		}
		writeSeen(b, tr, g, true)
		fmt.Fprintf(b, "- **%s:**\n", tr("label.flaws"))
		for i, f := range active {
			if i == maxFlaws {
				fmt.Fprintf(b, "  - %s\n", tr("kev.more", len(active)-maxFlaws))
				break
			}
			fmt.Fprintf(b, "  - %s\n", flawLine(tr, f))
		}
		if len(ruledOut) > 0 {
			fmt.Fprintf(b, "- **%s:** %s\n", tr("label.ruledout"), strings.Join(cveList(ruledOut), ", "))
		}
		if links := groupLinks(active); len(links) > 0 {
			fmt.Fprintf(b, "- **%s:** %s\n", tr("label.advisories"), strings.Join(links, " · "))
		}
		note := tr("kev.confidence")
		switch {
		case confirmed:
			note = tr("kev.confirmed", mdCode(g.Version))
		case packaged:
			note = tr("kev.packaged")
		}
		fmt.Fprintf(b, "\n> %s\n\n", note)
	case match.KindTLSExpired, match.KindTLSExpiring:
		f := g.Findings[0]
		date := ""
		if f.Expires != nil {
			date = f.Expires.UTC().Format("2006-01-02")
		}
		prefix := "tlss"
		if g.Kind == match.KindTLSExpired {
			prefix = "tlsx"
		}
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr(prefix+".title", where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr(prefix+".why", mdCode(f.Subject), date))
		fmt.Fprintf(b, "- **%s:** %s\n\n", tr("label.todo"), tr("tls.todo"))
	case match.KindExposedFile:
		f := g.Findings[0]
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("file.title."+f.TechID, where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("file.why."+f.TechID))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("file.todo."+f.TechID))
		fmt.Fprintf(b, "- **%s:** %s (%s)\n\n", tr("label.seen"), mdCode(f.URL), mdEscape(f.Evidence))
	case match.KindAdminExposed:
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("admin.title", mdEscape(g.Technology), where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("admin.why"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("admin.todo"))
		writeSeen(b, tr, g, false)
		b.WriteString("\n")
	case match.KindSecret:
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("secret.title", mdEscape(g.Technology)))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("secret.why"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("secret.todo"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.secret"), mdCode(g.Evidence))
		fmt.Fprintf(b, "- **%s:**\n", tr("label.found"))
		for i, f := range g.Findings {
			if i == maxFlaws {
				fmt.Fprintf(b, "  - %s\n", tr("sum.more", len(g.Findings)-maxFlaws))
				break
			}
			fmt.Fprintf(b, "  - %s\n", secretPlace(tr, f, true))
		}
		b.WriteString("\n")
	case match.KindBreach:
		withPasswords := 0
		for _, f := range g.Findings {
			if f.Passwords {
				withPasswords++
			}
		}
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("breach.title", mdEscape(g.Host)))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("breach.why", len(g.Findings), withPasswords))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("breach.todo"))
		fmt.Fprintf(b, "- **%s:**\n", tr("label.breaches"))
		for i, f := range g.Findings {
			if i == maxFlaws {
				fmt.Fprintf(b, "  - %s\n", tr("sum.more", len(g.Findings)-maxFlaws))
				break
			}
			parts := []string{"**" + mdEscape(f.Name) + "**", tr("breach.date", f.BreachDate), tr("breach.accounts", f.Accounts)}
			if f.Passwords {
				parts = append(parts, tr("breach.passwords"))
			}
			fmt.Fprintf(b, "  - %s\n", strings.Join(parts, " · "))
		}
		fmt.Fprintf(b, "- **%s:** %s\n\n", tr("label.source"), tr("breach.source"))
	}
}

// secretPlace says where a secret was found: a file and line, and the commit
// when it was found in the Git history.
func secretPlace(tr translator, f match.Finding, markdown bool) string {
	place := fmt.Sprintf("%s:%d", f.File, f.Line)
	commit := f.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if !markdown {
		if commit != "" {
			place += " (" + tr("secret.commit", commit) + ")"
		}
		return place
	}
	place = mdCode(place)
	if commit != "" {
		place += " · " + tr("secret.commit", mdCode(commit))
	}
	return place
}

func writeSeen(b *strings.Builder, tr translator, g match.Group, withVersion bool) {
	line := mdCode(g.URL)
	if g.Evidence != "" {
		line += " (" + mdCode(g.Evidence) + ")"
	}
	if withVersion {
		if g.Version != "" {
			line += " · " + tr("label.version", mdCode(g.Version))
		} else {
			line += " · " + tr("label.noversion")
		}
	}
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.seen"), line)
}

func flawLine(tr translator, f match.Finding) string {
	parts := []string{"**" + f.CVE + "**: " + mdEscape(f.Name), tr("kev.added", f.DateAdded)}
	if f.EPSS > 0 {
		parts = append(parts, "EPSS "+percent(f.EPSS))
	}
	if f.Ransomware {
		parts = append(parts, tr("kev.ransomware"))
	}
	if f.Forensics {
		parts = append(parts, tr("kev.forensicflag"))
	}
	if f.Confidence == match.ConfidenceVersion {
		parts = append(parts, tr("kev.versionhit"))
	}
	if f.Condition != "" {
		parts = append(parts, tr("kev.condition", mdEscape(f.Condition)))
	}
	return strings.Join(parts, " · ")
}

// newest returns the most recent date a flaw was added to KEV.
func newest(fs []match.Finding) string {
	n := ""
	for _, f := range fs {
		n = max(n, f.DateAdded)
	}
	return n
}

func cveList(fs []match.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.CVE)
	}
	return out
}

// groupLinks picks advisory links for a group: vendor advisories first, and
// none of CISA's US federal directive pages, which do not apply in the EU.
func groupLinks(fs []match.Finding) []string {
	var out []string
	seen := map[string]bool{}
	for i, f := range fs {
		if i == maxFlaws {
			break
		}
		for _, l := range f.Links {
			if seen[l] || strings.Contains(l, "cisa.gov/news-events/directives") {
				continue
			}
			seen[l] = true
			out = append(out, "<"+l+">")
			if len(out) == maxLinks {
				return out
			}
		}
	}
	return out
}

func percent(p float64) string {
	v := p * 100
	switch {
	case v < 1:
		return "<1%"
	case v >= 99.5:
		return ">99%"
	}
	return strconv.FormatFloat(v, 'f', 0, 64) + "%"
}

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// mdEscape keeps text from external sources (CISA data, page titles) from
// being read as Markdown or HTML.
func mdEscape(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
		"<", "&lt;", ">", "&gt;", "|", `\|`, "\n", " ", "\r", " ",
	)
	return r.Replace(s)
}

// mdCode shows a value verbatim as inline code.
func mdCode(s string) string {
	s = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s)
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

// Summary is a short chat message about a run: what is new, what was fixed
// and what is still open, in Slack's text format.
func Summary(open, added, resolved []match.Finding, first bool, m Meta) string {
	_, lines := SummaryLines(open, added, resolved, first, m)
	var b strings.Builder
	fmt.Fprintf(&b, "*Hejnal* · %s\n", chatEscape(m.Organization))
	for _, l := range lines {
		b.WriteString(chatEscape(l) + "\n")
	}
	return b.String()
}

// SummaryLines is the run summary as a plain title and lines, for any
// channel. Flaws the version check ruled out are left out.
func SummaryLines(open, added, resolved []match.Finding, first bool, m Meta) (string, []string) {
	tr := newTranslator(m.Lang)
	title := "Hejnal · " + m.Organization
	var lines []string
	og := match.Groups(match.Active(open))
	c := match.CountGroups(og)
	if first {
		lines = append(lines, tr("sum.first", len(og), c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	} else {
		lines = append(lines, tr("sum.counts", len(match.Groups(match.Active(added))), len(match.Groups(resolved)), len(og),
			c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	}
	list := match.Groups(match.Active(added))
	if first {
		list = og
	}
	const maxLines = 10
	for i, g := range list {
		if i == maxLines {
			lines = append(lines, tr("sum.more", len(list)-maxLines))
			break
		}
		lines = append(lines, fmt.Sprintf("• [%s] %s", tr("sev.short."+string(g.Severity)), groupTitle(tr, g)))
	}
	if len(og) > 0 {
		lines = append(lines, tr("sum.report"))
	}
	return title, lines
}

// chatEscape escapes the characters Slack-style chat formats treat as markup.
func chatEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func groupTitle(tr translator, g match.Group) string {
	where := hostPort(g.Host, g.Port)
	switch g.Kind {
	case match.KindKEV:
		var cves []string
		for i, f := range g.Findings {
			if i == 3 {
				cves = append(cves, fmt.Sprintf("+%d", len(g.Findings)-3))
				break
			}
			cves = append(cves, f.CVE)
		}
		return tr("kev.title", g.Technology, where) + ": " + strings.Join(cves, ", ")
	case match.KindTLSExpired:
		return tr("tlsx.title", where)
	case match.KindTLSExpiring:
		return tr("tlss.title", where)
	case match.KindAdminExposed:
		return tr("admin.title", g.Technology, where)
	case match.KindExposedFile:
		return tr("file.title."+g.TechID, where)
	case match.KindSecret:
		return tr("secret.title", g.Technology) + ": " + secretPlace(tr, g.Findings[0], false)
	case match.KindBreach:
		return tr("breach.title", g.Host)
	}
	return where
}
