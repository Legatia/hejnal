package report

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Legatia/hejnal/match"
)

// Issue is one item to fix, written as an issue for a tracker such as
// GitHub.
type Issue struct {
	// Item is the item's ID, as the fix list shows it.
	Item  string
	Title string
	// Body is Markdown. It starts with a hidden marker that carries the
	// item's ID, so the issue can be found again on later runs.
	Body string
}

// IssueOptions say how to write an issue.
type IssueOptions struct {
	Lang string
	// Owner is who looks after the system, if anyone is named.
	Owner string
	// Run is when the run that found the item was made.
	Run time.Time
	// Earlier is the acceptance of part of the item, when only what is new
	// since then is open.
	Earlier *match.Acceptance
}

// maxIssueTitle keeps titles inside GitHub's limit of 256 characters.
const maxIssueTitle = 200

// issueMarker starts the hidden first line of an issue's body.
const issueMarker = "<!-- hejnal:item:"

// IssueFor writes an item to fix as an issue: the same text as its entry in
// the fix list, with its priority and owner.
func IssueFor(g match.Group, o IssueOptions) Issue {
	tr := newTranslator(o.Lang)
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s -->\n", issueMarker, g.ID())
	fmt.Fprintf(&b, "- **%s:** %s\n", tr("hist.priority"), tr("sev.short."+string(g.Severity)))
	if o.Owner != "" {
		fmt.Fprintf(&b, "- **%s:** %s\n", tr("issue.owner"), mdEscape(o.Owner))
	}
	if len(g.Findings) > 0 {
		writeGroup(&b, tr, 0, g, o.Earlier)
	}
	body := strings.TrimRight(b.String(), "\n")
	if block := issueCheck(tr, g); block != "" {
		body += "\n\n" + block
	}
	body += "\n\n---\n" + tr("issue.footer", issueDay(o.Run), g.ID()) + "\n"

	title := ""
	if len(g.Findings) > 0 {
		title = itemTitle(tr, g)
	}
	title = strings.Join(strings.Fields(title), " ")
	if utf8.RuneCountInString(title) > maxIssueTitle {
		title = string([]rune(title)[:maxIssueTitle-1]) + "…"
	}
	return Issue{Item: g.ID(), Title: quietMentions(title), Body: quietMentions(body)}
}

// issueCheck writes what a person or a coding assistant needs to fix an
// item and to tell that the fix worked: where the item is, the version
// that fixes it, and the command that says whether Hejnal still finds it.
// The lines keep one form, so a program can read them. It returns "" for
// an item nothing here can be said about.
func issueCheck(tr translator, g match.Group) string {
	if len(g.Findings) == 0 {
		return ""
	}
	f := g.Findings[0]
	var lines []string
	add := func(label, value string) {
		if value != "" {
			lines = append(lines, fmt.Sprintf("- **%s:** %s", tr(label), value))
		}
	}
	var places []string
	for _, p := range Places(g) {
		places = append(places, mdCode(p))
	}
	check := ""
	switch g.Kind {
	case match.KindDependency:
		pkg := mdCode(g.Technology)
		if f.Ecosystem != "" {
			pkg += " (" + mdEscape(f.Ecosystem) + ")"
		}
		add("issue.check.package", pkg)
		add("issue.check.installed", mdCode(g.Version))
		add("issue.check.fixedin", mdCode(depFixedIn(g)))
		add("issue.check.where", strings.Join(places, ", "))
		// A package found only in a container image needs the image, which
		// the issue cannot name.
		if slices.ContainsFunc(g.Findings, func(f match.Finding) bool { return f.File != "" && !strings.Contains(f.File, ":") }) {
			check = codeCheckCommand(g)
		}
	case match.KindMisconfig:
		add("issue.check.where", strings.Join(places, ", "))
		check = codeCheckCommand(g)
	case match.KindSecret:
		add("issue.check.where", strings.Join(places, ", "))
	case match.KindKEV, match.KindEOL, match.KindAdminExposed, match.KindExposedFile, match.KindTLSExpired, match.KindTLSExpiring:
		addr := liveAddress(g)
		add("issue.check.system", mdCode(addr))
		if g.Technology != "" {
			// A product's name comes from the scanned system: as plain
			// text, a mention in it is made quiet.
			add("issue.check.product", mdEscape(strings.TrimSpace(g.Technology+" "+g.Version)))
		}
		if addr != "" {
			check = "hejnal live -item " + g.ID() + " " + addr
		}
	}
	if check != "" {
		lines = append(lines, fmt.Sprintf("- **%s:** %s", tr("issue.check.check"), mdCommand(check)))
	}
	if len(lines) == 0 {
		return ""
	}
	out := "**" + tr("issue.check.title") + "**\n\n" + strings.Join(lines, "\n")
	switch {
	case strings.HasPrefix(check, "hejnal code"):
		out += "\n\n" + tr("issue.check.code")
	case check != "":
		out += "\n\n" + tr("issue.check.live")
	}
	return out
}

// codeCheckCommand returns the command that says whether a code scan still
// finds an item, or "" when the project's name cannot go in a command.
func codeCheckCommand(g match.Group) string {
	if !safeArg.MatchString(g.Host) || strings.HasPrefix(g.Host, "-") {
		return ""
	}
	return "hejnal code scan -project " + g.Host + " -item " + g.ID()
}

// liveAddress returns the address `hejnal live` takes for the system an
// item is on: the scheme, host and port of where it was seen. It returns
// "" when the item names no address that is safe to put in a command.
func liveAddress(g match.Group) string {
	raw := g.URL
	if raw == "" {
		for _, f := range g.Findings {
			if f.URL != "" {
				raw = f.URL
				break
			}
		}
	}
	page, ok := safeURL(raw)
	if !ok {
		return ""
	}
	u, err := url.Parse(page)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// IssueItem returns the ID of the item an issue's body was written for, or
// "" when Hejnal did not write the issue.
func IssueItem(body string) string {
	rest, ok := strings.CutPrefix(strings.TrimLeft(body, "\ufeff \t\r\n"), issueMarker)
	if !ok {
		return ""
	}
	id, _, ok := strings.Cut(rest, " -->")
	if !ok || len(id) != len(match.ItemID("")) || strings.Trim(id, "0123456789abcdef") != "" {
		return ""
	}
	return id
}

// IssueGone is the comment for an issue whose item a run no longer finds.
// ruledOut is set when the run saw a version the flaws do not affect.
func IssueGone(lang string, run time.Time, ruledOut bool) string {
	key := "issue.gone"
	if ruledOut {
		key = "issue.ruledout"
	}
	return newTranslator(lang)(key, issueDay(run))
}

// IssueFound is the comment for a closed issue whose item a later run still
// finds. expired is the item's acceptance if it has ended.
func IssueFound(lang string, item string, run time.Time, expired *match.Acceptance) string {
	tr := newTranslator(lang)
	if expired != nil {
		return quietMentions(tr("issue.expired", mdEscape(expired.Until), issueDay(run)))
	}
	return tr("issue.found", issueDay(run), item)
}

// IssueAccepted is the comment for an issue whose item was accepted: until
// when, why and by whom.
func IssueAccepted(lang string, a match.Acceptance) string {
	tr := newTranslator(lang)
	lines := []string{tr("issue.accepted", mdEscape(a.Until)), ""}
	lines = append(lines, "- "+tr("issue.reason", mdEscape(a.Reason)))
	if a.By != "" {
		lines = append(lines, "- "+tr("issue.by", mdEscape(a.By)))
	}
	return quietMentions(strings.Join(lines, "\n"))
}

func issueDay(t time.Time) string {
	return t.UTC().Format(time.DateOnly)
}

// quietMentions puts an invisible word joiner after every @ outside code
// spans, so text from a scanned system cannot notify people or teams on
// GitHub. Code spans stay as they are: GitHub reads no mentions in them,
// and the commands in them must stay as written for copying.
func quietMentions(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = quietLine(line)
	}
	return strings.Join(lines, "\n")
}

func quietLine(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		switch c := line[i]; {
		case c == '\\' && i+1 < len(line) && line[i+1] == '`':
			// An escaped backtick opens no code span.
			b.WriteString("\\`")
			i += 2
		case c == '`':
			run := backticks(line[i:])
			end := closingRun(line[i+run:], run)
			if end < 0 {
				// No matching run: the backticks are plain text.
				b.WriteString(line[i : i+run])
				i += run
				continue
			}
			b.WriteString(line[i : i+run+end+run])
			i += run + end + run
		case c == '@':
			b.WriteString("@\u2060")
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// backticks counts the backticks s starts with.
func backticks(s string) int {
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	return n
}

// closingRun finds the next run of exactly n backticks in s, which closes a
// code span opened by n backticks, and returns where it starts, or -1.
func closingRun(s string, n int) int {
	for i := 0; i < len(s); {
		if s[i] != '`' {
			i++
			continue
		}
		run := backticks(s[i:])
		if run == n {
			return i
		}
		i += run
	}
	return -1
}
