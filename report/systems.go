package report

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/inventory"
)

// maxSystemLines is how many changes among the services seen a summary
// lists before summarising.
const maxSystemLines = 10

// SystemLines says what changed among the services Hejnal sees, as plain
// text for chat and the run summary: the counts, then a line for each host
// that is new, back or gone and each new version. Hosts are grouped across
// their ports. It returns nil when nothing changed.
func SystemLines(ch inventory.Changes, lang string) []string {
	if ch.Empty() {
		return nil
	}
	tr := newTranslator(lang)
	var added, gone, updated []string

	for _, rs := range byHost(ch.New, func(r inventory.Record) string { return r.Host }) {
		r := rs[0]
		back := !slices.ContainsFunc(rs, func(r inventory.Record) bool { return !r.FirstSeen.Before(r.LastSeen) })
		switch src := sourceText(tr, r.Source); {
		case back:
			first := slices.MinFunc(rs, func(a, b inventory.Record) int { return a.FirstSeen.Compare(b.FirstSeen) }).FirstSeen
			added = append(added, tr("sys.back", r.Host, portList(rs), first.UTC().Format(time.DateOnly)))
		case src != "":
			added = append(added, tr("sys.new", r.Host, portList(rs), productText(tr, rs), src))
		default:
			added = append(added, tr("sys.new.nosrc", r.Host, portList(rs), productText(tr, rs)))
		}
	}

	for _, gs := range byHost(ch.Gone, func(g inventory.Gone) string { return g.Host }) {
		rs := make([]inventory.Record, len(gs))
		for i, g := range gs {
			rs[i] = g.Record
		}
		key := "sys.gone"
		switch {
		case isAddress(gs[0].Host):
			key = "sys.gone.ip"
		case slices.ContainsFunc(gs, func(g inventory.Gone) bool { return g.Resolves }):
			key = "sys.gone.dns"
		}
		gone = append(gone, tr(key, gs[0].Host, portList(rs)))
	}

	for _, us := range byHost(ch.Updated, func(u inventory.VersionChange) string {
		return u.Host + "|" + u.Product + "|" + u.From + "|" + u.To
	}) {
		ports := make([]inventory.Record, len(us))
		for i, u := range us {
			ports[i] = inventory.Record{Port: u.Port}
		}
		u := us[0]
		updated = append(updated, tr("sys.updated", u.Product, u.From, u.To, u.Host, portList(ports)))
	}

	lines := []string{tr("sys.counts", len(added), len(gone), len(updated))}
	all := slices.Concat(added, gone, updated)
	for i, l := range all {
		if i == maxSystemLines {
			lines = append(lines, tr("sum.more", len(all)-maxSystemLines))
			break
		}
		lines = append(lines, l)
	}
	return lines
}

// byHost groups items that share a key, keeping the order in which each
// key first appears.
func byHost[T any](items []T, key func(T) string) [][]T {
	var out [][]T
	at := map[string]int{}
	for _, it := range items {
		k := key(it)
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], it)
	}
	return out
}

func portList(rs []inventory.Record) string {
	var ports []int
	for _, r := range rs {
		ports = append(ports, r.Port)
	}
	slices.Sort(ports)
	ports = slices.Compact(ports)
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// productText names the products on a host's services, once each, with
// their versions.
func productText(tr translator, rs []inventory.Record) string {
	var names, seen []string
	for _, r := range rs {
		for _, p := range r.Products {
			if slices.Contains(seen, p.ID) {
				continue
			}
			seen = append(seen, p.ID)
			names = append(names, strings.TrimSpace(p.Name+" "+p.Version))
		}
	}
	if len(names) == 0 {
		return tr("sys.noproduct")
	}
	return strings.Join(names, ", ")
}

// sourceText says how a host was found, or "" for a way this version does
// not know.
func sourceText(tr translator, source string) string {
	key := "sys.src." + source
	if _, ok := messages["en"][key]; !ok || source == "" {
		return ""
	}
	return tr(key)
}

func isAddress(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
