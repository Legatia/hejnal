package report

import (
	"fmt"
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
