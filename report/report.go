// Package report writes Hejnal's findings for people: a prioritised fix list,
// a short summary for chat, a monthly report, a NIS2 early-warning draft and
// a one-page overview for decision-makers. Reports are Markdown, except the
// overview, which is HTML; all are in English or Polish.
package report

import (
	"cmp"
	"fmt"
	"io"
	"net"
	"slices"
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
	EUVDDate     string
	EPSSDate     string
	// KEVFlaws is how many known exploited flaws were checked.
	KEVFlaws     int
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
		if m.EUVDDate != "" {
			b.WriteString(tr("fix.feeds.euvd", m.EUVDDate))
		}
		if m.EPSSDate != "" {
			b.WriteString(tr("fix.feeds.epss", m.EPSSDate))
		}
		b.WriteString(".\n\n")
	}

	// Items whose flaws the version check all ruled out go to the end, and
	// so do accepted findings, in a section of their own. An item with new
	// findings since it was accepted is listed with the new ones only.
	rest, acc := match.SplitAccepted(fs)
	accepted := match.Groups(acc)
	earlier := map[string]*match.Acceptance{}
	for _, g := range accepted {
		earlier[g.Key] = g.Acceptance()
	}
	var groups, fixed []match.Group
	for _, g := range match.Groups(rest) {
		switch {
		case g.Kind != match.KindKEV || len(match.Active(g.Findings)) > 0:
			groups = append(groups, g)
		case earlier[g.Key] == nil:
			// The ruled-out flaws of an accepted item are not listed again.
			fixed = append(fixed, g)
		}
	}
	c := match.CountGroups(groups)
	fmt.Fprintf(&b, "**%s**\n\n", tr("fix.summary", c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	if len(groups) == 0 {
		switch {
		case m.Services == 0:
			fmt.Fprintf(&b, "%s\n\n", tr("fix.empty"))
		case len(accepted) > 0:
			fmt.Fprintf(&b, "%s\n\n", tr("fix.accepted"))
		default:
			fmt.Fprintf(&b, "%s\n\n", tr("fix.none"))
		}
	}

	ids := map[string]int{}
	for _, sev := range match.Severities {
		for _, g := range groups {
			if g.Severity == sev {
				ids[g.Key] = len(ids) + 1
			}
		}
	}
	writeStart(&b, tr, groups, ids)
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
			writeGroup(&b, tr, n, g, earlier[g.Key])
		}
	}
	if len(fixed) > 0 {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", tr("fix.ruledout.title"), tr("fix.ruledout.intro"))
		for _, g := range fixed {
			fmt.Fprintf(&b, "- %s (%s): %s · %s\n", tr("kev.title", mdEscape(g.Technology), hostPort(g.Host, g.Port)),
				tr("label.version", mdCode(g.Version)), strings.Join(cveList(g.Findings), ", "), mdCode(g.ID()))
		}
		b.WriteString("\n")
	}
	writeAccepted(&b, tr, accepted)
	fmt.Fprintf(&b, "---\n\n%s\n", tr("fix.footer"))
	_, err := io.WriteString(w, b.String())
	return err
}

// writeGroup writes one item to fix. earlier is the acceptance of the item's
// other findings, when part of it was accepted.
func writeGroup(b *strings.Builder, tr translator, n int, g match.Group, earlier *match.Acceptance) {
	where := hostPort(g.Host, g.Port)
	// head writes the item's title and ID, and what was accepted of it.
	head := func(title string) {
		fmt.Fprintf(b, "### %d. %s · %s\n\n", n, title, mdCode(g.ID()))
		writeAcceptanceNotes(b, tr, g, earlier)
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.effort"), effortText(tr, Effort(g)))
	}
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
		head(tr("kev.title", mdEscape(g.Technology), where))
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
		note := tr("kev.confidence") + " " + tr("acc.hint", g.ID())
		switch {
		case confirmed:
			note = tr("kev.confirmed", mdCode(g.Version))
		case packaged:
			note = tr("kev.packaged") + " " + tr("acc.hint", g.ID())
		}
		proofLines(b, tr, g)
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
		head(tr(prefix+".title", where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr(prefix+".why", mdCode(f.Subject), date))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("tls.todo"))
		proofLines(b, tr, g)
		b.WriteString("\n")
	case match.KindExposedFile:
		f := g.Findings[0]
		head(tr("file.title."+f.TechID, where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("file.why."+f.TechID))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("file.todo."+f.TechID))
		fmt.Fprintf(b, "- **%s:** %s (%s)\n", tr("label.seen"), mdCode(f.URL), mdEscape(f.Evidence))
		proofLines(b, tr, g)
		b.WriteString("\n")
	case match.KindTakeover, match.KindEmail:
		f := g.Findings[0]
		key := kindKey(f)
		head(tr(key+".title", where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr(key+".why"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr(key+".todo"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.seen"), mdEscape(f.Evidence))
		proofLines(b, tr, g)
		b.WriteString("\n")
	case match.KindAdminExposed:
		head(tr("admin.title", mdEscape(g.Technology), where))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("admin.why"))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("admin.todo"))
		writeSeen(b, tr, g, false)
		proofLines(b, tr, g)
		b.WriteString("\n")
	case match.KindSecret:
		head(tr("secret.title", mdEscape(g.Technology)))
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
		proofLines(b, tr, g)
		b.WriteString("\n")
	case match.KindDependency:
		writeDependency(b, tr, g, func(t string) { head(mdEscape(t)) })
	case match.KindMisconfig:
		writeMisconfig(b, tr, g, func(t string) { head(mdEscape(t)) })
	case match.KindBreach:
		withPasswords := 0
		for _, f := range g.Findings {
			if f.Passwords {
				withPasswords++
			}
		}
		head(tr("breach.title", mdEscape(g.Host)))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("breach.why", len(g.Findings), withPasswords))
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("breach.todo"))
		fmt.Fprintf(b, "- **%s:**\n", tr("label.breaches"))
		for i, f := range g.Findings {
			if i == maxFlaws {
				fmt.Fprintf(b, "  - %s\n", tr("sum.more", len(g.Findings)-maxFlaws))
				break
			}
			parts := []string{"**" + mdEscape(f.Name) + "**", tr("breach.date", mdEscape(f.BreachDate)), tr("breach.accounts", f.Accounts)}
			if f.Passwords {
				parts = append(parts, tr("breach.passwords"))
			}
			fmt.Fprintf(b, "  - %s\n", strings.Join(parts, " · "))
		}
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.source"), tr("breach.source"))
		proofLines(b, tr, g)
		b.WriteString("\n")
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
	id := "**" + mdEscape(f.CVE) + "**"
	if f.EUVD != "" {
		id += " (" + mdEscape(f.EUVD) + ")"
	}
	parts := []string{id + ": " + mdEscape(f.Name)}
	if f.ENISAOnly() {
		parts = append(parts, tr("kev.enisaonly", mdEscape(f.DateAdded)))
	} else {
		parts = append(parts, tr("kev.added", mdEscape(f.DateAdded)))
		if days := daysBetween(f.ENISAEarlier, f.DateAdded); days == 1 {
			parts = append(parts, tr("kev.enisaearlier1", mdEscape(f.ENISAEarlier)))
		} else if days > 1 {
			parts = append(parts, tr("kev.enisaearlier", mdEscape(f.ENISAEarlier), days))
		}
	}
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

// daysBetween returns the number of days from one YYYY-MM-DD date to a
// later one, or 0.
func daysBetween(from, to string) int {
	a, err1 := time.Parse("2006-01-02", from)
	b, err2 := time.Parse("2006-01-02", to)
	if err1 != nil || err2 != nil || !b.After(a) {
		return 0
	}
	return int(b.Sub(a).Hours() / 24)
}

// newest returns the most recent date a flaw was added to a list of
// exploited flaws.
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
		out = append(out, mdEscape(f.CVE))
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
	if port == 0 {
		return host // a finding about the domain, such as its mail records
	}
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

// Summary is the run summary as plain text for a terminal: what is new,
// what was fixed and what is still open. Chat channels build their own
// message from SummaryLines.
func Summary(open, added, resolved []match.Finding, first bool, m Meta) string {
	title, lines := SummaryLines(open, added, resolved, first, m)
	var b strings.Builder
	b.WriteString(match.CleanNote(title) + "\n")
	for _, l := range lines {
		b.WriteString(match.CleanNote(l) + "\n")
	}
	return b.String()
}

// SummaryLines is the run summary as a plain title and lines, for any
// channel. Flaws the version check ruled out and accepted findings are left
// out; accepted items are only counted.
func SummaryLines(open, added, resolved []match.Finding, first bool, m Meta) (string, []string) {
	tr := newTranslator(m.Lang)
	title := "Hejnal · " + m.Organization
	var lines []string
	og := match.Groups(match.Open(open))
	c := match.CountGroups(og)
	if first {
		lines = append(lines, tr("sum.first", len(og), c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	} else {
		lines = append(lines, tr("sum.counts", len(match.Groups(match.Open(added))), len(match.Groups(resolved)), len(og),
			c[match.Critical], c[match.High], c[match.Medium], c[match.Low]))
	}
	if _, acc := match.SplitAccepted(open); len(acc) > 0 {
		lines[0] += tr("sum.accepted", len(match.Groups(acc)))
	}
	list := match.Groups(match.Open(added))
	if first {
		list = og
	}
	const maxLines = 10
	for i, g := range list {
		if i == maxLines {
			lines = append(lines, tr("sum.more", len(list)-maxLines))
			break
		}
		line := fmt.Sprintf("• [%s] %s", tr("sev.short."+string(g.Severity)), groupTitle(tr, g))
		if g.ExpiredAcceptance() != nil {
			line += " · " + tr("sum.expired")
		}
		lines = append(lines, line)
	}
	if len(og) > 0 {
		lines = append(lines, tr("sum.report"))
	}
	return title, lines
}

// ItemTitle names an item to fix in plain text, such as "WordPress on
// www.example.com:443", in the given language.
func ItemTitle(g match.Group, lang string) string {
	return itemTitle(newTranslator(lang), g)
}

// GroupTitle names an item with its flaws, as the fix list does.
func GroupTitle(g match.Group, lang string) string {
	return groupTitle(newTranslator(lang), g)
}

// ItemText says why an item matters and what to do about it, as plain
// text in the given language, for trackers and other tools.
func ItemText(g match.Group, lang string) (why, todo string) {
	if len(g.Findings) == 0 {
		return "", ""
	}
	return itemText(newTranslator(lang), g)
}

// groupTitle names an item in plain text, with its first flaws for known
// exploited ones.
func groupTitle(tr translator, g match.Group) string {
	var ids []string
	switch g.Kind {
	case match.KindDependency:
		// Two advisories about one flaw carry the same CVE; name it once.
		for _, f := range match.Active(g.Findings) {
			if id := cmp.Or(f.CVE, f.Advisory); !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	case match.KindKEV:
		for _, f := range g.Findings {
			ids = append(ids, f.CVE)
		}
	default:
		return itemTitle(tr, g)
	}
	const maxIDs = 3
	if len(ids) > maxIDs {
		ids = append(ids[:maxIDs:maxIDs], fmt.Sprintf("+%d", len(ids)-maxIDs))
	}
	return itemTitle(tr, g) + ": " + strings.Join(ids, ", ")
}

func itemTitle(tr translator, g match.Group) string {
	where := hostPort(g.Host, g.Port)
	switch g.Kind {
	case match.KindKEV:
		return tr("kev.title", g.Technology, where)
	case match.KindTLSExpired:
		return tr("tlsx.title", where)
	case match.KindTLSExpiring:
		return tr("tlss.title", where)
	case match.KindAdminExposed:
		return tr("admin.title", g.Technology, where)
	case match.KindExposedFile:
		return tr("file.title."+g.TechID, where)
	case match.KindTakeover, match.KindEmail:
		return tr(kindKey(g.Findings[0])+".title", where)
	case match.KindSecret:
		return tr("secret.title", g.Technology) + ": " + secretPlace(tr, g.Findings[0], false)
	case match.KindBreach:
		return tr("breach.title", g.Host)
	case match.KindDependency:
		return tr("dep.title", g.Technology, g.Version, ecosystemLabel(g.Findings[0].Ecosystem), g.Host)
	case match.KindMisconfig:
		return tr("misconfig.title."+g.TechID, g.Technology)
	}
	return where
}

// kindKey is the start of the message keys for a takeover or mail finding.
func kindKey(f match.Finding) string {
	if f.Kind == match.KindEmail {
		return "email." + f.TechID
	}
	return "takeover"
}
