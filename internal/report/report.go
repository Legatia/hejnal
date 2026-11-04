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

	"github.com/Legatia/hejnal/internal/match"
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

	groups := match.Groups(fs)
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
	fmt.Fprintf(&b, "---\n\n%s\n", tr("fix.footer"))
	_, err := io.WriteString(w, b.String())
	return err
}

func writeGroup(b *strings.Builder, tr translator, n int, g match.Group) {
	where := hostPort(g.Host, g.Port)
	switch g.Kind {
	case match.KindKEV:
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("kev.title", mdEscape(g.Technology), where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("kev.why", len(g.Findings), g.Newest()))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("kev.todo"))
		if g.Forensics() {
			fmt.Fprintf(b, "- **%s:** %s\n", tr("label.compromise"), tr("kev.forensic"))
		}
		writeSeen(b, tr, g, true)
		fmt.Fprintf(b, "- **%s:**\n", tr("label.flaws"))
		for i, f := range g.Findings {
			if i == maxFlaws {
				fmt.Fprintf(b, "  - %s\n", tr("kev.more", len(g.Findings)-maxFlaws))
				break
			}
			fmt.Fprintf(b, "  - %s\n", flawLine(tr, f))
		}
		if links := groupLinks(g); len(links) > 0 {
			fmt.Fprintf(b, "- **%s:** %s\n", tr("label.advisories"), strings.Join(links, " · "))
		}
		fmt.Fprintf(b, "\n> %s\n\n", tr("kev.confidence"))
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
	case match.KindAdminExposed:
		fmt.Fprintf(b, "### %d. %s\n\n", n, tr("admin.title", mdEscape(g.Technology), where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("admin.why"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("admin.todo"))
		writeSeen(b, tr, g, false)
		b.WriteString("\n")
	}
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
	return strings.Join(parts, " · ")
}

// groupLinks picks advisory links for a group: vendor advisories first, and
// none of CISA's US federal directive pages, which do not apply in the EU.
func groupLinks(g match.Group) []string {
	var out []string
	seen := map[string]bool{}
	for i, f := range g.Findings {
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
// and what is still open.
func Summary(open, added, resolved []match.Finding, first bool, m Meta) string {
	tr := newTranslator(m.Lang)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", tr("sum.title", chatEscape(m.Organization)))
	og := match.Groups(open)
	c := match.CountGroups(og)
	if first {
		fmt.Fprintf(&b, "%s\n", tr("sum.first", len(og), c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	} else {
		fmt.Fprintf(&b, "%s\n", tr("sum.counts", len(match.Groups(added)), len(match.Groups(resolved)), len(og),
			c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	}
	list := match.Groups(added)
	if first {
		list = og
	}
	const maxLines = 10
	for i, g := range list {
		if i == maxLines {
			fmt.Fprintf(&b, "%s\n", tr("sum.more", len(list)-maxLines))
			break
		}
		fmt.Fprintf(&b, "• [%s] %s\n", tr("sev.short."+string(g.Severity)), chatEscape(groupTitle(tr, g)))
	}
	if len(og) > 0 {
		b.WriteString(tr("sum.report"))
		b.WriteString("\n")
	}
	return b.String()
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
	}
	return where
}
