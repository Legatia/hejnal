package inventory

import (
	"cmp"
	"slices"
	"time"
)

// Record is what Hejnal remembers of one service across runs: where it
// answered, how its host was found, what ran there, and when it was first
// and last seen.
type Record struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Source is how the host was found when the service first answered.
	Source   string    `json:"source,omitempty"`
	Products []Product `json:"products,omitempty"`
	// FirstSeen and LastSeen are the first and the latest run in which the
	// service answered.
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// Missed counts the runs in a row in which it did not answer.
	Missed int `json:"missed,omitempty"`
	// Gone is when it was taken as gone: after Missing runs in a row
	// without an answer.
	Gone *time.Time `json:"gone,omitempty"`
}

// Product is a product recognised on a service, and the version it showed.
type Product struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Changes are what one or more runs changed among the services Hejnal sees.
type Changes struct {
	// New are services that answered for the first time, or again after
	// they were gone.
	New []Record `json:"new,omitempty"`
	// Gone are services that stopped answering.
	Gone []Gone `json:"gone,omitempty"`
	// Updated are products whose version changed on a service.
	Updated []VersionChange `json:"updated,omitempty"`
}

// Gone is a service that stopped answering. Resolves says whether its host
// name still resolves in the run that found it gone, which is when its DNS
// record is worth removing.
type Gone struct {
	Record
	Resolves bool `json:"resolves,omitempty"`
}

// VersionChange is a product that showed another version than before.
type VersionChange struct {
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	Product string    `json:"product"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	At      time.Time `json:"at"`
}

// Empty reports whether nothing changed.
func (c Changes) Empty() bool { return len(c.New)+len(c.Gone)+len(c.Updated) == 0 }

// Add appends later changes to c.
func (c *Changes) Add(later Changes) {
	c.New = append(c.New, later.New...)
	c.Gone = append(c.Gone, later.Gone...)
	c.Updated = append(c.Updated, later.Updated...)
}

// Trim drops changes older than keep at now and keeps at most limit of each
// kind, the latest, so that changes nobody collects do not pile up.
func (c *Changes) Trim(now time.Time, keep time.Duration, limit int) {
	cut := now.Add(-keep)
	c.New = latest(slices.DeleteFunc(c.New, func(r Record) bool { return r.LastSeen.Before(cut) }), limit)
	c.Gone = latest(slices.DeleteFunc(c.Gone, func(g Gone) bool { return g.Gone != nil && g.Gone.Before(cut) }), limit)
	c.Updated = latest(slices.DeleteFunc(c.Updated, func(u VersionChange) bool { return u.At.Before(cut) }), limit)
}

func latest[T any](s []T, limit int) []T {
	if len(s) > limit {
		return s[len(s)-limit:]
	}
	return s
}

const (
	// Missing is how many runs in a row a service must not answer before it
	// counts as gone, so that one timeout does not report it.
	Missing = 2
	// keepGone is how long a gone service stays on record.
	keepGone = 400 * 24 * time.Hour
)

type place struct {
	host string
	port int
}

// Update folds an inventory into the records of what answered before, and
// returns the new records and what changed. inScope tells whether a host is
// still in the scope; records of hosts that left it are dropped without a
// word, since they did not go away. The first run, with no records yet,
// changes nothing: everything in it is simply recorded. A run in which no
// service answered says nothing about which services are gone either, so
// it leaves the records of missing services as they were.
func Update(records []Record, inv *Inventory, now time.Time, inScope func(host string) bool) ([]Record, Changes) {
	type current struct {
		source   string
		products []Product
	}
	answered := map[place]current{}
	resolves := map[string]bool{}
	for _, a := range inv.Assets {
		resolves[a.Host] = len(a.IPs) > 0
		for _, s := range a.Services {
			p := place{a.Host, s.Port}
			if _, ok := answered[p]; !ok {
				answered[p] = current{a.Source, products(s.Technologies)}
			}
		}
	}
	first := len(records) == 0
	var out []Record
	var ch Changes
	known := map[place]bool{}
	for _, r := range records {
		p := place{r.Host, r.Port}
		if !inScope(r.Host) || known[p] {
			continue
		}
		known[p] = true
		if cur, ok := answered[p]; ok {
			back := r.Gone != nil
			if !back {
				ch.Updated = append(ch.Updated, updates(r, cur.products, now)...)
			}
			r.Products = keepVersions(r.Products, cur.products)
			r.LastSeen, r.Missed, r.Gone = now, 0, nil
			if back {
				// It answers again: news, like a new service.
				ch.New = append(ch.New, r)
			}
		} else if len(answered) > 0 && r.Gone == nil {
			r.Missed++
			if r.Missed >= Missing {
				at := now
				r.Gone = &at
				ch.Gone = append(ch.Gone, Gone{Record: r, Resolves: resolves[r.Host]})
			}
		}
		if r.Gone != nil && now.Sub(*r.Gone) > keepGone {
			continue
		}
		out = append(out, r)
	}
	for p, cur := range answered {
		if known[p] {
			continue
		}
		r := Record{Host: p.host, Port: p.port, Source: cur.source, Products: cur.products, FirstSeen: now, LastSeen: now}
		out = append(out, r)
		if !first {
			ch.New = append(ch.New, r)
		}
	}
	byPlace := func(a, b Record) int { return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port)) }
	slices.SortFunc(out, byPlace)
	slices.SortFunc(ch.New, byPlace)
	slices.SortFunc(ch.Gone, func(a, b Gone) int { return byPlace(a.Record, b.Record) })
	slices.SortFunc(ch.Updated, func(a, b VersionChange) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port), cmp.Compare(a.Product, b.Product))
	})
	return out, ch
}

// products lists the products on a service, once each.
func products(ts []Technology) []Product {
	var out []Product
	for _, t := range ts {
		if !slices.ContainsFunc(out, func(p Product) bool { return p.ID == t.ID }) {
			out = append(out, Product{ID: t.ID, Name: t.Name, Version: t.Version})
		}
	}
	return out
}

// updates returns the products that show another version than before. A
// product that hides its version this time, or did before, is no news.
func updates(r Record, now []Product, at time.Time) []VersionChange {
	var out []VersionChange
	for _, p := range now {
		i := slices.IndexFunc(r.Products, func(q Product) bool { return q.ID == p.ID })
		if i < 0 || p.Version == "" || r.Products[i].Version == "" || p.Version == r.Products[i].Version {
			continue
		}
		out = append(out, VersionChange{Host: r.Host, Port: r.Port, Product: p.Name, From: r.Products[i].Version, To: p.Version, At: at})
	}
	return out
}

// keepVersions returns the products seen now, with the version seen before
// for a product that hides it this time.
func keepVersions(before, now []Product) []Product {
	out := slices.Clone(now)
	for i, p := range out {
		if p.Version != "" {
			continue
		}
		if j := slices.IndexFunc(before, func(q Product) bool { return q.ID == p.ID }); j >= 0 {
			out[i].Version = before[j].Version
		}
	}
	return out
}
