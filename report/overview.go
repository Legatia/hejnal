package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// The overview is one page for decision-makers: a verdict, the few items to
// fix first and what the organisation exposes. It is a self-contained HTML
// file, laid out to print or save as PDF on A4.

//go:embed overview.html
var overviewHTML string

// pageCSS styles the HTML reports.
//
//go:embed report.css
var pageCSS string

var overviewTmpl = template.Must(template.New("overview").Parse(overviewHTML))

// overviewItems is how many items the overview lists before pointing to the
// full fix list.
const overviewItems = 5

// OverviewOptions are the parts of an overview that do not come from the
// findings.
type OverviewOptions struct {
	// By names who prepared the report, such as a company that ran the
	// scan for the organisation.
	By string
	// Inventory, when known, gives the overview of what is exposed.
	Inventory *inventory.Inventory
	// History is the earlier runs, for when each item was first seen.
	History []*state.Snapshot
}

type ovStat struct {
	Value string
	Label string
}

type ovFlaw struct {
	CVE, EUVD, Lists, Since string
}

type ovItem struct {
	N         int
	Severity  string
	SevLabel  string
	Title     string
	Why, Todo string
	Effort    string
	Sure      string
	Window    string
	Seen      string
	Forensic  string
	Flaws     []ovFlaw
	MoreFlaws string
	Links     []string
}

type ovCategory struct {
	Label    string
	Services int
	Examples string
}

type overviewData struct {
	CSS                        template.CSS
	Lang, Title, Org, Date, By string
	Level                      string
	Headline, Verdict          string
	Stats                      []ovStat
	Items                      []ovItem
	More                       string
	Accepted                   string
	Categories                 []ovCategory
	Sources, Method, Limits    string
	L                          map[string]string
	Footer                     string
}

// Overview writes the one-page overview of the latest run.
func Overview(w io.Writer, fs []match.Finding, m Meta, o OverviewOptions) error {
	tr := newTranslator(m.Lang)
	lang := m.Lang
	if !ValidLang(lang) {
		lang = "en"
	}
	d := overviewData{
		CSS:   template.CSS(pageCSS),
		Lang:  lang,
		Title: tr("ov.title"),
		Org:   m.Organization,
		Date:  tr("ov.date", m.GeneratedAt.UTC().Format("2006-01-02")),
		L: map[string]string{
			"fixfirst": tr("ov.fixfirst"), "where": tr("ov.where"), "why": tr("label.why"), "todo": tr("label.todo"), "effort": tr("label.effort"), "sure": tr("label.howsure"),
			"flaw": tr("ov.flaw"), "lists": tr("ov.lists"), "since": tr("ov.since"), "compromise": tr("label.compromise"),
			"advisories": tr("label.advisories"), "exposed": tr("ov.exposed"), "exposedintro": tr("ov.exposedintro"),
			"type": tr("ov.type"), "services": tr("ov.services"), "examples": tr("ov.examples"), "method": tr("ov.method"),
			"for": tr("ov.for"),
		},
		Footer: tr("ov.footer"),
	}
	if o.By != "" {
		d.By = tr("ov.by", o.By)
	}

	// The items to fix, as in the fix list: accepted findings and items
	// whose flaws were all ruled out are left out.
	rest, acc := match.SplitAccepted(fs)
	var groups []match.Group
	for _, g := range match.Groups(rest) {
		if g.Kind != match.KindKEV || len(match.Active(g.Findings)) > 0 {
			groups = append(groups, g)
		}
	}
	sevRank := func(s match.Severity) int { return slices.Index(match.Severities, s) }
	sort.SliceStable(groups, func(i, j int) bool { return sevRank(groups[i].Severity) < sevRank(groups[j].Severity) })
	c := match.CountGroups(groups)
	urgent := c[match.Critical] + c[match.High]
	exploited := 0
	for _, g := range groups {
		if g.Kind == match.KindKEV {
			exploited += len(match.Active(g.Findings))
		}
	}
	switch {
	case m.Services == 0:
		d.Level, d.Headline, d.Verdict = "empty", tr("ov.empty.head"), tr("ov.empty.text")
	case urgent > 0:
		d.Level, d.Headline, d.Verdict = "urgent", tr("ov.urgent.head", urgent), tr("ov.urgent.text")
	case len(groups) > 0:
		d.Level, d.Headline, d.Verdict = "attention", tr("ov.attention.head", len(groups)), tr("ov.attention.text")
	default:
		d.Level, d.Headline, d.Verdict = "clear", tr("ov.clear.head"), tr("ov.clear.text", m.Services)
	}

	stat := func(n int, key string) ovStat { return ovStat{number(lang, n), tr(key)} }
	d.Stats = []ovStat{stat(m.Assets, "ov.stat.hosts"), stat(m.Services, "ov.stat.services"), stat(m.Technologies, "ov.stat.products")}
	if m.KEVFlaws > 0 {
		d.Stats = append(d.Stats, stat(m.KEVFlaws, "ov.stat.checked"))
	}
	d.Stats = append(d.Stats, stat(exploited, "ov.stat.exploited"), stat(len(groups), "ov.stat.items"))

	firstSeen := firstSeenDates(o.History)
	for i, g := range groups {
		if i == overviewItems {
			if rest := len(groups) - overviewItems; rest == 1 {
				d.More = tr("ov.more1")
			} else {
				d.More = tr("ov.more", rest)
			}
			break
		}
		d.Items = append(d.Items, overviewItem(tr, i+1, g, m.GeneratedAt, firstSeen))
	}
	if ag := match.Groups(acc); len(ag) > 0 {
		d.Accepted = tr("ov.accepted", len(ag))
	}
	d.Categories = exposedCategories(tr, o.Inventory)

	if m.KEVVersion != "" {
		var b strings.Builder
		b.WriteString(tr("fix.feeds", m.KEVVersion))
		if m.EUVDDate != "" {
			b.WriteString(tr("fix.feeds.euvd", m.EUVDDate))
		}
		if m.EPSSDate != "" {
			b.WriteString(tr("fix.feeds.epss", m.EPSSDate))
		}
		b.WriteString(".")
		d.Sources = b.String()
	}
	d.Method, d.Limits = tr("ov.method.text"), tr("ov.limits")
	return overviewTmpl.Execute(w, d)
}

func overviewItem(tr translator, n int, g match.Group, now time.Time, firstSeen map[string]time.Time) ovItem {
	it := ovItem{N: n, Severity: string(g.Severity), SevLabel: tr("sev.short." + string(g.Severity)), Title: itemTitle(tr, g)}
	why, todo := itemText(tr, g)
	it.Why, it.Todo = plain(why), plain(todo)
	it.Effort = effortText(tr, Effort(g))
	it.Sure = proofOf(tr, g).Summary
	// When Hejnal first saw the item, if before this run.
	var seen time.Time
	for _, f := range g.Findings {
		if t, ok := firstSeen[f.Key]; ok && (seen.IsZero() || t.Before(seen)) {
			seen = t
		}
	}
	today := now.UTC().Format("2006-01-02")
	if !seen.IsZero() && seen.UTC().Format("2006-01-02") < today {
		it.Seen = tr("ov.seen", seen.UTC().Format("2006-01-02"))
	}
	if g.Kind != match.KindKEV {
		return it
	}
	active := match.Active(g.Findings)
	earliest := ""
	for i, f := range active {
		listed := f.FirstListed()
		if earliest == "" || (listed != "" && listed < earliest) {
			earliest = listed
		}
		if i < 4 {
			fl := ovFlaw{CVE: f.CVE, EUVD: f.EUVD, Since: listed, Lists: strings.Join(f.ListedBy, ", ")}
			if fl.Lists == "" {
				fl.Lists = match.ListCISA
			}
			it.Flaws = append(it.Flaws, fl)
		}
	}
	if len(active) > 4 {
		it.MoreFlaws = tr("kev.more", len(active)-4)
	}
	switch days := daysBetween(earliest, today); {
	case days == 1:
		it.Window = tr("ov.window1", earliest)
	case days > 1:
		it.Window = tr("ov.window", earliest, days)
	}
	if g.Forensics() {
		it.Forensic = tr("kev.forensic")
	}
	links := groupLinks(active)
	for i, l := range links {
		if i == 2 {
			break
		}
		// groupLinks gives Markdown autolinks.
		it.Links = append(it.Links, strings.Trim(l, "<>"))
	}
	return it
}

// number formats a count the way the language writes it: 1,783 in English;
// in Polish, a space groups thousands from five digits on.
func number(lang string, n int) string {
	s := strconv.Itoa(n)
	sep := ","
	if lang == "pl" {
		if n < 10000 {
			return s
		}
		sep = "\u00a0"
	}
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + sep + s[i:]
	}
	return s
}

// itemText returns why an item matters and what to do, as plain text.
func itemText(tr translator, g match.Group) (why, todo string) {
	f := g.Findings[0]
	switch g.Kind {
	case match.KindKEV:
		active := match.Active(g.Findings)
		return tr("kev.why", len(active), newest(active)), tr("kev.todo")
	case match.KindTLSExpired, match.KindTLSExpiring:
		prefix := "tlss"
		if g.Kind == match.KindTLSExpired {
			prefix = "tlsx"
		}
		date := ""
		if f.Expires != nil {
			date = f.Expires.UTC().Format("2006-01-02")
		}
		return tr(prefix+".why", f.Subject, date), tr("tls.todo")
	case match.KindExposedFile:
		return tr("file.why." + f.TechID), tr("file.todo." + f.TechID)
	case match.KindTakeover, match.KindEmail:
		return tr(kindKey(f) + ".why"), tr(kindKey(f) + ".todo")
	case match.KindAdminExposed:
		return tr("admin.why"), tr("admin.todo")
	case match.KindSecret:
		return tr("secret.why"), tr("secret.todo")
	case match.KindBreach:
		withPasswords := 0
		for _, f := range g.Findings {
			if f.Passwords {
				withPasswords++
			}
		}
		return tr("breach.why", len(g.Findings), withPasswords), tr("breach.todo")
	}
	return "", ""
}

var mdLink = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)

// plain removes the Markdown some translations use.
func plain(s string) string {
	s = mdLink.ReplaceAllString(s, "$1")
	return strings.NewReplacer("`", "", "**", "").Replace(s)
}

// firstSeenDates returns when each finding was first seen in the history.
func firstSeenDates(history []*state.Snapshot) map[string]time.Time {
	out := map[string]time.Time{}
	for _, s := range history {
		for _, f := range match.Active(s.Findings) {
			if t, ok := out[f.Key]; !ok || s.GeneratedAt.Before(t) {
				out[f.Key] = s.GeneratedAt
			}
		}
	}
	return out
}

// categoryOrder lists the kinds of product an attacker looks for first.
var categoryOrder = []string{"edge", "remote-access", "network", "mail", "file-transfer", "collaboration", "virtualization",
	"mdm", "backup", "security", "camera", "industrial", "voip", "storage", "admin", "itsm", "monitoring", "devops",
	"business", "data", "ai", "hosting", "cms", "framework", "server", "language", "printing", "media", "chat"}

// exposedCategories counts the services running each kind of product.
func exposedCategories(tr translator, inv *inventory.Inventory) []ovCategory {
	if inv == nil {
		return nil
	}
	services := map[string]int{}
	names := map[string][]string{}
	for _, a := range inv.Assets {
		for _, s := range a.Services {
			seen := map[string]bool{}
			for _, t := range s.Technologies {
				cat := t.Category
				if !slices.Contains(categoryOrder, cat) {
					cat = "other"
				}
				if !seen[cat] {
					seen[cat] = true
					services[cat]++
				}
				if !slices.Contains(names[cat], t.Name) {
					names[cat] = append(names[cat], t.Name)
				}
			}
		}
	}
	var out []ovCategory
	for _, cat := range append(slices.Clone(categoryOrder), "other") {
		if services[cat] == 0 {
			continue
		}
		ex := names[cat]
		sort.Strings(ex)
		more := ""
		if len(ex) > 4 {
			more = fmt.Sprintf(" +%d", len(ex)-4)
			ex = ex[:4]
		}
		out = append(out, ovCategory{Label: tr("cat." + cat), Services: services[cat], Examples: strings.Join(ex, ", ") + more})
	}
	return out
}
