package report

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// The evidence report shows, from the saved runs, that an organisation
// monitors its internet-facing systems and how fast it fixes what is found:
// for insurers, auditors and customers' security questionnaires.

//go:embed evidence.html
var evidenceHTML string

var evidenceTmpl = template.Must(template.New("evidence").Parse(evidenceHTML))

// EvidenceOptions say what period the evidence covers and who prepared it.
type EvidenceOptions struct {
	// Since leaves out runs before it; zero means all saved runs.
	Since time.Time
	By    string
}

// Exposure is one item to fix across the runs: when Hejnal first and last
// saw it, and when a run first found it gone.
type Exposure struct {
	Group     match.Group
	FirstSeen time.Time
	LastSeen  time.Time
	// Fixed is the first run after LastSeen, or zero while the item is
	// still there.
	Fixed time.Time
	// Accepted is set when the latest run marks the item as accepted.
	Accepted bool
	// Listed is the earliest date a list of exploited flaws named one of
	// the item's flaws, for known exploited flaws.
	Listed string
	// AtStart is set when the item was already there in the first run, so
	// it was exposed for longer than Hejnal saw.
	AtStart bool
	// RuledOut is set when Hejnal only ever saw the product without a
	// version, and the run at Fixed saw a version outside the affected
	// range. The flaw was never confirmed, so the item counts neither as
	// found nor as fixed.
	RuledOut bool
	// confirmed is set once a run saw the item with more than a product
	// name: an affected version, or the problem itself.
	confirmed bool
}

// Open reports whether the item was still there in the latest run.
func (e Exposure) Open() bool { return e.Fixed.IsZero() }

// Days returns how long the item was seen exposed: until it was fixed, or
// until now while it is open.
func (e Exposure) Days(now time.Time) float64 {
	end := e.Fixed
	if end.IsZero() {
		end = now
	}
	return end.Sub(e.FirstSeen).Hours() / 24
}

// Exposures works out every item's exposure from the runs, oldest first.
// Runs that reached no services are left out, unless none did, since they
// would make everything look fixed.
func Exposures(history []*state.Snapshot) (runs []*state.Snapshot, unreachable int, out []Exposure) {
	runs = slices.Clone(history)
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].GeneratedAt.Before(runs[j].GeneratedAt) })
	if slices.ContainsFunc(runs, func(s *state.Snapshot) bool { return s.Services > 0 }) {
		kept := runs[:0]
		for _, s := range runs {
			if s.Services > 0 {
				kept = append(kept, s)
			} else {
				unreachable++
			}
		}
		runs = kept
	}
	if len(runs) == 0 {
		return nil, unreachable, nil
	}
	idx := map[string]int{}
	present := map[string]bool{}
	ruledOut := map[string]bool{}
	for i, s := range runs {
		clear(present)
		clear(ruledOut)
		for _, f := range s.Findings {
			if f.RuledOut() {
				ruledOut[match.GroupKey(f)] = true
			}
		}
		for _, g := range match.Groups(match.Active(s.Findings)) {
			present[g.Key] = true
			j, ok := idx[g.Key]
			if !ok {
				j = len(out)
				idx[g.Key] = j
				out = append(out, Exposure{FirstSeen: s.GeneratedAt, AtStart: i == 0})
			}
			e := &out[j]
			e.Group, e.LastSeen, e.Fixed, e.RuledOut = g, s.GeneratedAt, time.Time{}, false
			e.Accepted = slices.ContainsFunc(g.Findings, func(f match.Finding) bool { return f.Accepted != nil })
			for _, f := range g.Findings {
				if f.Confidence != match.ConfidenceProduct {
					e.confirmed = true
				}
				if l := f.FirstListed(); l != "" && (e.Listed == "" || l < e.Listed) {
					e.Listed = l
				}
			}
		}
		// Items missing from this run were fixed by it, if they were there
		// in the run before. An item flagged without a version, which this
		// run rules out by the version it saw, was a false alarm instead.
		for key, j := range idx {
			if !present[key] && out[j].Fixed.IsZero() && out[j].LastSeen.Before(s.GeneratedAt) {
				out[j].Fixed = s.GeneratedAt
				out[j].RuledOut = ruledOut[key] && !out[j].confirmed
			}
		}
	}
	return runs, unreachable, out
}

type evQA struct{ Q, A string }

// evControl is one control of a security framework this evidence supports.
type evControl struct{ Framework, ID, Topic, How string }

// evidenceControls are the controls the evidence speaks to, with message
// keys for their topic and how the evidence supports them. Topics are
// described in Hejnal's words: the frameworks' own texts are not copied.
var evidenceControls = []struct{ framework, id, key string }{
	{"SOC 2", "CC7.1", "soc2.cc71"},
	{"SOC 2", "CC4.1", "soc2.cc41"},
	{"ISO/IEC 27001:2022", "A.8.8", "iso.a88"},
	{"ISO/IEC 27001:2022", "A.5.7", "iso.a57"},
	{"NIS2", "Art. 21(2)(e)", "nis2.e"},
}

type evRow struct {
	Title, Severity, SevLabel, Listed, FirstSeen, Fixed, Days, Status, StatusClass string
}

type evMonth struct {
	Month          string
	Runs           int
	Services       int
	Open, Urgent   int
	FixedExploited int
	MedianFix      string
}

type evidenceData struct {
	CSS                        template.CSS
	Lang, Title, Org, Date, By string
	Period, Statement          string
	Stats                      []ovStat
	QA                         []evQA
	Controls                   []evControl
	Rows                       []evRow
	MoreRows                   string
	NoExploited                string
	Months                     []evMonth
	Accepted                   []evRow
	Unreachable                string
	Sources, Method, Limits    string
	Fingerprint                string
	L                          map[string]string
	Footer                     string
	Empty                      string
}

// evidenceRows is how many exploited-flaw items the evidence lists.
const evidenceRows = 40

// Evidence writes the monitoring evidence for the saved runs.
func Evidence(w io.Writer, history []*state.Snapshot, m Meta, o EvidenceOptions) error {
	tr := newTranslator(m.Lang)
	lang := m.Lang
	if !ValidLang(lang) {
		lang = "en"
	}
	day := func(t time.Time) string { return t.UTC().Format("2006-01-02") }
	d := evidenceData{
		CSS:   template.CSS(pageCSS),
		Lang:  lang,
		Title: tr("ev.title"),
		Org:   m.Organization,
		Date:  tr("ev.date", day(m.GeneratedAt)),
		L: map[string]string{
			"for": tr("ov.for"), "qa": tr("ev.qa"), "exposure": tr("ev.exposure"), "exposureintro": tr("ev.exposureintro"),
			"item": tr("ev.item"), "listed": tr("ev.listed"), "seen": tr("ev.seen"), "fixed": tr("ev.fixed"),
			"days": tr("ev.days"), "status": tr("ev.status"), "months": tr("ev.months"), "month": tr("ev.month"),
			"runs": tr("ev.runs"), "services": tr("ov.services"), "open": tr("ev.open"), "urgent": tr("ev.urgent"),
			"fixedexp": tr("ev.fixedexp"), "median": tr("ev.median"), "accepted": tr("ev.accepted"),
			"acceptedintro": tr("ev.acceptedintro"), "method": tr("ov.method"), "fingerprint": tr("ev.fingerprint"),
			"controls": tr("ev.controls"), "controlsintro": tr("ev.controlsintro"), "framework": tr("ev.framework"),
			"control": tr("ev.control"), "how": tr("ev.how"),
		},
		Footer: tr("ov.footer"),
	}
	if o.By != "" {
		d.By = tr("ov.by", o.By)
	}

	var in []*state.Snapshot
	for _, s := range history {
		if o.Since.IsZero() || !s.GeneratedAt.Before(o.Since) {
			in = append(in, s)
		}
	}
	runs, unreachable, exps := Exposures(in)
	if len(runs) == 0 {
		d.Empty = tr("ev.empty")
		return evidenceTmpl.Execute(w, d)
	}
	first, last := runs[0], runs[len(runs)-1]
	now := last.GeneratedAt
	d.Period = tr("ev.period", day(first.GeneratedAt), day(last.GeneratedAt))
	if unreachable > 0 {
		d.Unreachable = tr("ev.unreachable", unreachable)
	}

	// How regularly the runs happened.
	gap := 0.0
	for i := 1; i < len(runs); i++ {
		gap = max(gap, runs[i].GeneratedAt.Sub(runs[i-1].GeneratedAt).Hours()/24)
	}
	span := last.GeneratedAt.Sub(first.GeneratedAt).Hours() / 24
	every := 0.0
	if len(runs) > 1 {
		every = span / float64(len(runs)-1)
	}

	// Exploited flaws: how long each was exposed and how fast it was fixed.
	// Items ruled out by version were never confirmed: they are listed, but
	// count neither as found nor as fixed.
	var kev, ruledOut []Exposure
	var allFix, kevFix []float64
	var accepted []Exposure
	for _, e := range exps {
		if e.RuledOut {
			if e.Group.Kind == match.KindKEV {
				ruledOut = append(ruledOut, e)
			}
			continue
		}
		if !e.Open() {
			allFix = append(allFix, e.Days(now))
		}
		if e.Accepted && e.Open() {
			accepted = append(accepted, e)
		}
		if e.Group.Kind == match.KindKEV {
			kev = append(kev, e)
			if !e.Open() {
				kevFix = append(kevFix, e.Days(now))
			}
		}
	}
	within := func(days float64) int {
		n := 0
		for _, v := range kevFix {
			if v <= days {
				n++
			}
		}
		return n
	}
	openKEV, oldest := 0, 0.0
	for _, e := range kev {
		if e.Open() && !e.Accepted {
			openKEV++
			oldest = max(oldest, e.Days(now))
		}
	}

	d.Statement = tr("ev.statement", m.Organization, day(first.GeneratedAt), len(runs), day(last.GeneratedAt))
	stat := func(v string, key string) ovStat { return ovStat{v, tr(key)} }
	d.Stats = []ovStat{
		stat(number(lang, len(runs)), "ev.stat.runs"),
		stat(oneDecimal(lang, every), "ev.stat.every"),
		stat(number(lang, len(kev)), "ev.stat.kev"),
		stat(number(lang, len(kevFix)), "ev.stat.kevfixed"),
	}
	if len(kevFix) > 0 {
		d.Stats = append(d.Stats, stat(oneDecimal(lang, medianOf(kevFix)), "ev.stat.median"))
	}
	d.Stats = append(d.Stats, stat(number(lang, openKEV), "ev.stat.open"))

	// Answers to common questionnaire questions, from the data alone.
	feeds := tr("ev.a.feeds.cisa")
	if last.EUVDDate != "" {
		feeds = tr("ev.a.feeds.both")
	}
	checked := ""
	if last.KEVFlaws > 0 {
		checked = " " + tr("ev.a.checked", number(lang, last.KEVFlaws))
	}
	d.QA = []evQA{
		{tr("ev.q.scan"), tr("ev.a.scan", len(runs), day(first.GeneratedAt), day(last.GeneratedAt), oneDecimal(lang, every), oneDecimal(lang, gap))},
		{tr("ev.q.kev"), tr("ev.a.kev", feeds) + checked},
	}
	fixA := tr("ev.a.fix.none")
	if len(kevFix) > 0 {
		fixA = tr("ev.a.fix", oneDecimal(lang, medianOf(kevFix)), within(7), len(kevFix), within(30))
	} else if len(kev) > 0 {
		fixA = tr("ev.a.fix.notyet")
	}
	if openKEV > 0 {
		fixA += " " + tr("ev.a.fix.open", openKEV, oneDecimal(lang, oldest))
	}
	if len(allFix) > len(kevFix) {
		fixA += " " + tr("ev.a.fix.all", oneDecimal(lang, medianOf(allFix)), len(allFix))
	}
	d.QA = append(d.QA, evQA{tr("ev.q.fix"), fixA})
	accA := tr("ev.a.acc.none")
	if len(accepted) > 0 {
		accA = tr("ev.a.acc", len(accepted))
	}
	d.QA = append(d.QA, evQA{tr("ev.q.acc"), accA})
	for _, c := range evidenceControls {
		d.Controls = append(d.Controls, evControl{c.framework, c.id, tr("ev.c." + c.key + ".topic"), tr("ev.c." + c.key + ".how")})
	}

	// The exploited-flaw items, open ones first, then by first seen.
	sort.SliceStable(kev, func(i, j int) bool {
		if kev[i].Open() != kev[j].Open() {
			return kev[i].Open()
		}
		return kev[i].FirstSeen.After(kev[j].FirstSeen)
	})
	sort.SliceStable(ruledOut, func(i, j int) bool { return ruledOut[i].FirstSeen.After(ruledOut[j].FirstSeen) })
	listed := slices.Concat(kev, ruledOut)
	for i, e := range listed {
		if i == evidenceRows {
			d.MoreRows = tr("ev.more", len(listed)-evidenceRows)
			break
		}
		d.Rows = append(d.Rows, exposureRow(tr, lang, e, now))
	}
	if len(listed) == 0 {
		d.NoExploited = tr("ev.noexploited")
	}
	for _, e := range accepted {
		r := exposureRow(tr, lang, e, now)
		if a := e.Group.Acceptance(); a != nil {
			r.Status = tr("ev.acc.row", a.Reason, a.By, a.Until)
		}
		d.Accepted = append(d.Accepted, r)
	}
	d.Months = evidenceMonths(lang, runs, exps)

	if last.KEVVersion != "" {
		d.Sources = tr("fix.feeds", last.KEVVersion)
		if last.EUVDDate != "" {
			d.Sources += tr("fix.feeds.euvd", last.EUVDDate)
		}
		d.Sources += "."
	}
	d.Method, d.Limits = tr("ev.method"), tr("ev.limits")
	d.Fingerprint = runsFingerprint(runs)
	return evidenceTmpl.Execute(w, d)
}

func exposureRow(tr translator, lang string, e Exposure, now time.Time) evRow {
	g := e.Group
	r := evRow{
		Title:     itemTitle(tr, g),
		Severity:  string(g.Severity),
		SevLabel:  tr("sev.short." + string(g.Severity)),
		Listed:    e.Listed,
		FirstSeen: e.FirstSeen.UTC().Format("2006-01-02"),
		Days:      oneDecimal(lang, e.Days(now)),
	}
	if e.AtStart {
		// Exposed before monitoring began: at least this long.
		r.Days = "≥ " + r.Days
	}
	switch {
	case e.RuledOut:
		// Never confirmed, so there is no exposure to count.
		r.Days = ""
		r.Status, r.StatusClass = tr("label.ruledout"), "fixed"
	case e.Accepted && e.Open():
		r.Status, r.StatusClass = tr("ev.st.accepted"), "medium"
	case e.Open():
		r.Status, r.StatusClass = tr("ev.st.open"), "critical"
	default:
		r.Fixed = e.Fixed.UTC().Format("2006-01-02")
		r.Status, r.StatusClass = tr("ev.st.fixed"), "fixed"
	}
	return r
}

// evidenceMonths summarises each month: runs, size, what was open at its
// end and the exploited-flaw items fixed during it.
func evidenceMonths(lang string, runs []*state.Snapshot, exps []Exposure) []evMonth {
	var out []evMonth
	idx := map[string]int{}
	for _, s := range runs {
		key := s.GeneratedAt.UTC().Format("2006-01")
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, evMonth{Month: monthName(lang, s.GeneratedAt.UTC())})
		}
		open := match.Groups(match.Open(s.Findings))
		c := match.CountGroups(open)
		out[i].Runs++
		out[i].Services = s.Services
		out[i].Open, out[i].Urgent = len(open), c[match.Critical]+c[match.High]
	}
	fixes := map[int][]float64{}
	for _, e := range exps {
		if e.Group.Kind != match.KindKEV || e.Open() || e.RuledOut {
			continue
		}
		if i, ok := idx[e.Fixed.UTC().Format("2006-01")]; ok {
			out[i].FixedExploited++
			fixes[i] = append(fixes[i], e.Days(e.Fixed))
		}
	}
	for i, v := range fixes {
		out[i].MedianFix = oneDecimal(lang, medianOf(v))
	}
	return out
}

// medianOf returns the median of v, which must not be empty.
func medianOf(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 0 {
		return (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return s[len(s)/2]
}

// oneDecimal formats days with one decimal, with the language's separator.
func oneDecimal(lang string, v float64) string {
	s := fmt.Sprintf("%.1f", v)
	if lang == "pl" {
		s = s[:len(s)-2] + "," + s[len(s)-1:]
	}
	return s
}

// runsFingerprint hashes the runs the report used, so the report can be
// checked against the saved runs later.
func runsFingerprint(runs []*state.Snapshot) string {
	h := sha256.New()
	for _, s := range runs {
		data, err := json.Marshal(s)
		if err != nil {
			continue
		}
		h.Write(data)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
