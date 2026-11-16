package report

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// The history of a system is what the record of services and the saved
// runs say about one host: when it first answered, the versions it showed,
// the items found on it and when they were fixed, and when it went away.

// System is one host's history.
type System struct {
	Host string `json:"host"`
	// Source is how the host was found.
	Source string `json:"source,omitempty"`
	// FirstSeen and LastSeen are the first and the latest run in which any
	// of its services answered.
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// Gone is when its last service was taken as gone. It is nil while a
	// service still answers.
	Gone     *time.Time      `json:"gone,omitempty"`
	Services []SystemService `json:"services"`
	Counts   SystemCounts    `json:"items"`
	// Items and Events are filled in for the history of one system, and
	// left out of a list of systems.
	Items  []SystemItem  `json:"itemList,omitempty"`
	Events []SystemEvent `json:"events,omitempty"`
}

// SystemService is one port of a system that answered.
type SystemService struct {
	Port      int                 `json:"port"`
	Products  []inventory.Product `json:"products,omitempty"`
	FirstSeen time.Time           `json:"firstSeen"`
	LastSeen  time.Time           `json:"lastSeen"`
	// Missed counts the latest runs in a row without an answer.
	Missed int        `json:"missed,omitempty"`
	Gone   *time.Time `json:"gone,omitempty"`
}

// SystemCounts count the items found on a system in the saved runs. Items
// ruled out by version were never confirmed and are not counted.
type SystemCounts struct {
	Found    int `json:"found"`
	Fixed    int `json:"fixed"`
	Open     int `json:"open"`
	Accepted int `json:"accepted"`
}

// SystemItem is one item found on a system.
type SystemItem struct {
	ID        string     `json:"id"`
	Kind      match.Kind `json:"kind"`
	Title     string     `json:"title"`
	Port      int        `json:"port,omitempty"`
	Severity  string     `json:"severity"`
	FirstSeen time.Time  `json:"firstSeen"`
	Fixed     *time.Time `json:"fixed,omitempty"`
	// BeforeMonitoring is set when the item was there in the first run.
	BeforeMonitoring bool   `json:"beforeMonitoring,omitempty"`
	Status           string `json:"status"` // open, fixed, accepted or ruled-out
}

// Kinds of events in a system's history.
const (
	SystemFirstSeen = "first-seen"     // a service answered for the first time
	SystemVersion   = "version"        // a product showed another version
	SystemGone      = "gone"           // a service stopped answering
	SystemBack      = "back"           // a service answered again
	SystemItemFound = "item-found"     // an item to fix was found
	SystemItemFixed = "item-fixed"     // a run found the item gone
	SystemItemRuled = "item-ruled-out" // a version ruled the item out
)

// SystemEvent is one dated entry in a system's history.
type SystemEvent struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	// Ports are the services the event is about, for the kinds about
	// services.
	Ports []int `json:"ports,omitempty"`
	// Product, From and To describe a version change.
	Product string `json:"product,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	// Item, Title and Severity describe the item, for the kinds about items.
	Item     string `json:"item,omitempty"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	// BeforeMonitoring is set on an item found in the first run.
	BeforeMonitoring bool `json:"beforeMonitoring,omitempty"`
	// Days is how long a fixed item was seen exposed.
	Days float64 `json:"days,omitempty"`
}

// CleanHost writes a host name the way the records do: lower case, without
// a trailing dot or surrounding space.
func CleanHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// Systems lists every host on record with its services and the number of
// items found on it in the saved runs, by host name.
func Systems(records []inventory.Record, history []*state.Snapshot, lang string) []System {
	_, _, exps := Exposures(history)
	return buildSystems(records, exps, newTranslator(lang), "")
}

// SystemHistory returns the history of one host, with its items and
// events. It reports false for a host that is not on record.
func SystemHistory(host string, records []inventory.Record, history []*state.Snapshot, lang string) (System, bool) {
	host = CleanHost(host)
	if host == "" {
		return System{}, false
	}
	_, _, exps := Exposures(history)
	all := buildSystems(records, exps, newTranslator(lang), host)
	if len(all) == 0 {
		return System{}, false
	}
	return all[0], true
}

// buildSystems builds the systems on record. With only set, it builds that
// host alone, with its items and events.
func buildSystems(records []inventory.Record, exps []Exposure, tr translator, only string) []System {
	var out []System
	at := map[string]int{}
	for _, r := range records {
		host := CleanHost(r.Host)
		if only != "" && host != only {
			continue
		}
		i, ok := at[host]
		if !ok {
			i = len(out)
			at[host] = i
			out = append(out, System{Host: host, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen})
		}
		s := &out[i]
		if s.Source == "" {
			s.Source = r.Source
		}
		if r.FirstSeen.Before(s.FirstSeen) {
			s.FirstSeen = r.FirstSeen
		}
		if r.LastSeen.After(s.LastSeen) {
			s.LastSeen = r.LastSeen
		}
		s.Services = append(s.Services, SystemService{Port: r.Port, Products: r.Products,
			FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Missed: r.Missed, Gone: r.Gone})
		if only != "" {
			s.Events = append(s.Events, serviceEvents(r)...)
		}
	}
	for i := range out {
		s := &out[i]
		slices.SortFunc(s.Services, func(a, b SystemService) int { return cmp.Compare(a.Port, b.Port) })
		// The system is gone once every service is: since the last of them.
		for _, sv := range s.Services {
			if sv.Gone == nil {
				s.Gone = nil
				break
			}
			if s.Gone == nil || sv.Gone.After(*s.Gone) {
				s.Gone = sv.Gone
			}
		}
	}
	for _, e := range exps {
		i, ok := at[CleanHost(e.Group.Host)]
		if !ok {
			continue
		}
		s := &out[i]
		status := "open"
		switch {
		case e.RuledOut:
			status = "ruled-out"
		case !e.Open():
			status = "fixed"
			s.Counts.Fixed++
		case e.Accepted:
			status = "accepted"
			s.Counts.Accepted++
		default:
			s.Counts.Open++
		}
		if !e.RuledOut {
			s.Counts.Found++
		}
		if only == "" {
			continue
		}
		g := e.Group
		it := SystemItem{ID: g.ID(), Kind: g.Kind, Title: itemTitle(tr, g), Port: g.Port, Severity: string(g.Severity),
			FirstSeen: e.FirstSeen, BeforeMonitoring: e.AtStart, Status: status}
		found := SystemEvent{At: e.FirstSeen, Kind: SystemItemFound, Item: it.ID, Title: it.Title, Severity: it.Severity, BeforeMonitoring: e.AtStart}
		s.Events = append(s.Events, found)
		if !e.Open() {
			fixed := e.Fixed
			done := SystemEvent{At: fixed, Kind: SystemItemFixed, Item: it.ID, Title: it.Title, Severity: it.Severity, Days: round1(e.Days(fixed))}
			if e.RuledOut {
				done.Kind, done.Days = SystemItemRuled, 0
			} else {
				it.Fixed = &fixed
			}
			s.Events = append(s.Events, done)
		}
		s.Items = append(s.Items, it)
	}
	for i := range out {
		s := &out[i]
		s.Events = mergeEvents(s.Events)
		// Open items first, then the latest found.
		slices.SortStableFunc(s.Items, func(a, b SystemItem) int {
			if ao, bo := a.Fixed == nil && a.Status != "ruled-out", b.Fixed == nil && b.Status != "ruled-out"; ao != bo {
				if ao {
					return -1
				}
				return 1
			}
			return b.FirstSeen.Compare(a.FirstSeen)
		})
	}
	slices.SortFunc(out, func(a, b System) int { return cmp.Compare(a.Host, b.Host) })
	return out
}

// serviceEvents are the dated events of one service: its first answer, and
// what its record kept since.
func serviceEvents(r inventory.Record) []SystemEvent {
	out := []SystemEvent{{At: r.FirstSeen, Kind: SystemFirstSeen, Ports: []int{r.Port}}}
	for _, e := range r.Events {
		ev := SystemEvent{At: e.At, Ports: []int{r.Port}}
		switch e.Kind {
		case inventory.EventVersion:
			ev.Kind, ev.Product, ev.From, ev.To = SystemVersion, e.Product, e.From, e.To
		case inventory.EventGone:
			ev.Kind = SystemGone
		case inventory.EventBack:
			ev.Kind = SystemBack
		default:
			continue // a kind a later version wrote
		}
		out = append(out, ev)
	}
	return out
}

// eventOrder puts events of one run in the order they read best.
var eventOrder = []string{SystemFirstSeen, SystemBack, SystemVersion, SystemGone, SystemItemFound, SystemItemFixed, SystemItemRuled}

// mergeEvents sorts events by time and joins the ones that say the same of
// several ports of the host.
func mergeEvents(evs []SystemEvent) []SystemEvent {
	slices.SortStableFunc(evs, func(a, b SystemEvent) int {
		return cmp.Or(a.At.Compare(b.At),
			cmp.Compare(slices.Index(eventOrder, a.Kind), slices.Index(eventOrder, b.Kind)),
			cmp.Compare(a.Product, b.Product), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	var out []SystemEvent
	for _, e := range evs {
		if n := len(out); n > 0 && len(e.Ports) > 0 {
			p := &out[n-1]
			if p.At.Equal(e.At) && p.Kind == e.Kind && p.Product == e.Product && p.From == e.From && p.To == e.To {
				p.Ports = append(p.Ports, e.Ports...)
				slices.Sort(p.Ports)
				p.Ports = slices.Compact(p.Ports)
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// maxTimeline is how many events the history of a system lists.
const maxTimeline = 60

// SystemReport writes the history of one system in Markdown.
func SystemReport(w io.Writer, s System, m Meta) error {
	tr := newTranslator(m.Lang)
	day := func(t time.Time) string { return t.UTC().Format(time.DateOnly) }
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", tr("hist.title"), mdEscape(s.Host))
	fmt.Fprintf(&b, "%s\n\n", tr("hist.generated", m.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")))

	fmt.Fprintf(&b, "- **%s:** %s\n", tr("hist.first"), day(s.FirstSeen))
	fmt.Fprintf(&b, "- **%s:** %s\n", tr("hist.last"), day(s.LastSeen))
	if src := sourceText(tr, s.Source); src != "" {
		fmt.Fprintf(&b, "- **%s:** %s\n", tr("hist.source"), src)
	}
	fmt.Fprintf(&b, "- **%s:** %s\n", tr("ev.status"), systemStatus(tr, s))
	fmt.Fprintf(&b, "- **%s:** %s\n\n", tr("hist.items"), tr("hist.counts", s.Counts.Found, s.Counts.Fixed, s.Counts.Open, s.Counts.Accepted))

	fmt.Fprintf(&b, "## %s\n\n", tr("ov.services"))
	fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n|---|---|---|---|---|\n", tr("hist.port"), tr("hist.products"), tr("hist.first"), tr("hist.last"), tr("ev.status"))
	for _, sv := range s.Services {
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", sv.Port, mdEscape(productNames(tr, sv.Products)), day(sv.FirstSeen), day(sv.LastSeen), serviceStatus(tr, sv))
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## %s\n\n", tr("hist.items"))
	if len(s.Items) == 0 {
		fmt.Fprintf(&b, "%s\n\n", tr("hist.noitems"))
	} else {
		fmt.Fprintf(&b, "| %s | ID | %s | %s | %s | %s |\n|---|---|---|---|---|---|\n", tr("ev.item"), tr("hist.priority"), tr("ev.seen"), tr("ev.fixed"), tr("ev.status"))
		for _, it := range s.Items {
			fixed := ""
			if it.Fixed != nil {
				fixed = day(*it.Fixed)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(it.Title), mdCode(it.ID), tr("sev.short."+it.Severity), day(it.FirstSeen), fixed, itemStatus(tr, it.Status))
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## %s\n\n", tr("hist.timeline"))
	evs := s.Events
	if len(evs) > maxTimeline {
		fmt.Fprintf(&b, "%s\n\n", tr("hist.earlier", len(evs)-maxTimeline))
		evs = evs[len(evs)-maxTimeline:]
	}
	for _, e := range evs {
		fmt.Fprintf(&b, "- %s · %s\n", day(e.At), eventText(tr, m.Lang, e))
	}
	fmt.Fprintf(&b, "\n---\n\n%s\n", tr("hist.footer"))
	_, err := io.WriteString(w, b.String())
	return err
}

// SystemList writes the systems on record in Markdown.
func SystemList(w io.Writer, systems []System, m Meta) error {
	tr := newTranslator(m.Lang)
	day := func(t time.Time) string { return t.UTC().Format(time.DateOnly) }
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", tr("hist.list.title"), mdEscape(m.Organization))
	fmt.Fprintf(&b, "%s\n\n", tr("hist.generated", m.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")))
	gone := 0
	for _, s := range systems {
		if s.Gone != nil {
			gone++
		}
	}
	fmt.Fprintf(&b, "**%s**\n\n", tr("hist.list.counts", len(systems), len(systems)-gone, gone))
	if len(systems) == 0 {
		fmt.Fprintf(&b, "%s\n", tr("hist.list.none"))
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n|---|---|---|---|---|---|---|\n", tr("hist.system"), tr("hist.ports"),
		tr("hist.products"), tr("hist.first"), tr("hist.last"), tr("hist.open"), tr("ev.status"))
	for _, s := range systems {
		var ports []string
		var products []inventory.Product
		for _, sv := range s.Services {
			ports = append(ports, strconv.Itoa(sv.Port))
			for _, p := range sv.Products {
				if !slices.ContainsFunc(products, func(q inventory.Product) bool { return q.ID == p.ID }) {
					products = append(products, p)
				}
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d | %s |\n", mdEscape(s.Host), strings.Join(ports, ", "),
			mdEscape(productNames(tr, products)), day(s.FirstSeen), day(s.LastSeen), s.Counts.Open, systemStatus(tr, s))
	}
	fmt.Fprintf(&b, "\n---\n\n%s\n", tr("hist.list.footer"))
	_, err := io.WriteString(w, b.String())
	return err
}

// productNames names products with their versions.
func productNames(tr translator, ps []inventory.Product) string {
	if len(ps) == 0 {
		return tr("sys.noproduct")
	}
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = strings.TrimSpace(p.Name + " " + p.Version)
	}
	return strings.Join(names, ", ")
}

func systemStatus(tr translator, s System) string {
	if s.Gone != nil {
		return tr("hist.st.gone", s.Gone.UTC().Format(time.DateOnly))
	}
	return tr("hist.st.up")
}

func serviceStatus(tr translator, sv SystemService) string {
	switch {
	case sv.Gone != nil:
		return tr("hist.st.gone", sv.Gone.UTC().Format(time.DateOnly))
	case sv.Missed > 0:
		return tr("hist.st.missed")
	}
	return tr("hist.st.up")
}

func itemStatus(tr translator, status string) string {
	switch status {
	case "fixed":
		return tr("ev.st.fixed")
	case "accepted":
		return tr("ev.st.accepted")
	case "ruled-out":
		return tr("label.ruledout")
	}
	return tr("ev.st.open")
}

// eventText says one event in words.
func eventText(tr translator, lang string, e SystemEvent) string {
	ports := make([]string, len(e.Ports))
	for i, p := range e.Ports {
		ports[i] = strconv.Itoa(p)
	}
	port := strings.Join(ports, ", ")
	item := func() string {
		return mdEscape(e.Title) + " · " + tr("sev.short."+e.Severity) + " · " + mdCode(e.Item)
	}
	switch e.Kind {
	case SystemFirstSeen:
		return tr("hist.ev.first", port)
	case SystemVersion:
		return tr("hist.ev.version", mdEscape(e.Product), mdEscape(e.From), mdEscape(e.To), port)
	case SystemGone:
		return tr("hist.ev.gone", port)
	case SystemBack:
		return tr("hist.ev.back", port)
	case SystemItemFound:
		if e.BeforeMonitoring {
			return tr("hist.ev.found.start", item())
		}
		return tr("hist.ev.found", item())
	case SystemItemFixed:
		return tr("hist.ev.fixed", item(), oneDecimal(lang, e.Days))
	case SystemItemRuled:
		return tr("hist.ev.ruledout", item())
	}
	return e.Kind
}
