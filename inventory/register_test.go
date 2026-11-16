package inventory

import (
	"slices"
	"strconv"
	"testing"
	"time"
)

var day0 = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)

func at(days int) time.Time { return day0.AddDate(0, 0, days) }

func everywhere(string) bool { return true }

// shopInventory has shop.example.com on ports 80 and 443 with nginx at the
// given version, and the hosts given with nothing answering.
func shopInventory(nginx string, extra ...Asset) *Inventory {
	tech := []Technology{{ID: "nginx", Name: "nginx", Version: nginx}, {ID: "php", Name: "PHP", Version: "8.2.10"}}
	inv := &Inventory{Assets: []Asset{{Host: "shop.example.com", Source: "domain", IPs: []string{"192.0.2.10"}, Services: []Service{
		{Port: 80, Technologies: tech[:1]},
		{Port: 443, Technologies: tech},
	}}}}
	inv.Assets = append(inv.Assets, extra...)
	return inv
}

func places(rs []Record) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Host+":"+strconv.Itoa(r.Port))
	}
	return out
}

func TestFirstRunOnlyRecords(t *testing.T) {
	recs, ch := Update(nil, shopInventory("1.24.0"), at(0), everywhere)
	if !ch.Empty() {
		t.Errorf("the first run reported changes: %+v", ch)
	}
	if got := places(recs); !slices.Equal(got, []string{"shop.example.com:80", "shop.example.com:443"}) {
		t.Fatalf("records %v", got)
	}
	r := recs[1]
	if r.Source != "domain" || !r.FirstSeen.Equal(at(0)) || !r.LastSeen.Equal(at(0)) || len(r.Products) != 2 {
		t.Errorf("record %+v", r)
	}
}

func TestNewServicesAndVersions(t *testing.T) {
	recs, _ := Update(nil, shopInventory("1.24.0"), at(0), everywhere)
	api := Asset{Host: "api.example.com", Source: "ct", IPs: []string{"192.0.2.11"}, Services: []Service{
		{Port: 443, Technologies: []Technology{{ID: "grafana", Name: "Grafana", Version: "10.2.3"}}},
	}}
	recs, ch := Update(recs, shopInventory("1.30.6", api), at(1), everywhere)
	if got := places(ch.New); !slices.Equal(got, []string{"api.example.com:443"}) {
		t.Errorf("new %v", got)
	}
	if ch.New[0].Source != "ct" || ch.New[0].Products[0].Name != "Grafana" {
		t.Errorf("new service %+v", ch.New[0])
	}
	want := []VersionChange{
		{Host: "shop.example.com", Port: 80, Product: "nginx", From: "1.24.0", To: "1.30.6", At: at(1)},
		{Host: "shop.example.com", Port: 443, Product: "nginx", From: "1.24.0", To: "1.30.6", At: at(1)},
	}
	if !slices.Equal(ch.Updated, want) {
		t.Errorf("updated %+v, want %+v", ch.Updated, want)
	}
	if len(ch.Gone) != 0 || len(recs) != 3 {
		t.Errorf("gone %+v, %d records", ch.Gone, len(recs))
	}
	// A version hidden this time is no news, and the record keeps the last
	// one seen.
	recs, ch = Update(recs, shopInventory("", api), at(2), everywhere)
	if !ch.Empty() {
		t.Errorf("a hidden version reported %+v", ch)
	}
	if v := recs[2].Products[0].Version; v != "1.30.6" {
		t.Errorf("kept version %q", v)
	}
}

func TestGoneAfterTwoMissedRuns(t *testing.T) {
	old := Asset{Host: "old.example.com", Source: "ct", IPs: []string{"192.0.2.12"}, Services: []Service{{Port: 443}}}
	recs, _ := Update(nil, shopInventory("1.24.0", old), at(0), everywhere)

	// One run without an answer could be a timeout.
	stillResolves := Asset{Host: "old.example.com", Source: "ct", IPs: []string{"192.0.2.12"}}
	recs, ch := Update(recs, shopInventory("1.24.0", stillResolves), at(1), everywhere)
	if !ch.Empty() {
		t.Fatalf("one missed run reported %+v", ch)
	}
	// A run in which nothing answered says nothing.
	recs, ch = Update(recs, &Inventory{}, at(2), everywhere)
	if !ch.Empty() || recs[0].Missed != 1 {
		t.Fatalf("an empty run changed %+v (missed %d)", ch, recs[0].Missed)
	}
	// The second missed run makes it gone; its name still resolves.
	recs, ch = Update(recs, shopInventory("1.24.0", stillResolves), at(3), everywhere)
	if len(ch.Gone) != 1 || ch.Gone[0].Host != "old.example.com" || !ch.Gone[0].Resolves || !ch.Gone[0].Gone.Equal(at(3)) {
		t.Fatalf("gone %+v", ch.Gone)
	}
	// It is reported once.
	recs, ch = Update(recs, shopInventory("1.24.0"), at(4), everywhere)
	if !ch.Empty() {
		t.Errorf("gone reported again: %+v", ch)
	}
	// Answering again is news, and the record keeps its first day.
	recs, ch = Update(recs, shopInventory("1.24.0", old), at(5), everywhere)
	if len(ch.New) != 1 || !ch.New[0].FirstSeen.Equal(at(0)) || ch.New[0].Gone != nil {
		t.Errorf("back %+v", ch.New)
	}
	// Gone without its name: the DNS record is gone too.
	recs, _ = Update(recs, shopInventory("1.24.0"), at(6), everywhere)
	_, ch = Update(recs, shopInventory("1.24.0"), at(7), everywhere)
	if len(ch.Gone) != 1 || ch.Gone[0].Resolves {
		t.Errorf("gone without a name %+v", ch.Gone)
	}
}

func TestRecordsOutOfScopeAreDropped(t *testing.T) {
	old := Asset{Host: "old.example.com", Source: "ct", IPs: []string{"192.0.2.12"}, Services: []Service{{Port: 443}}}
	recs, _ := Update(nil, shopInventory("1.24.0", old), at(0), everywhere)
	notOld := func(h string) bool { return h != "old.example.com" }
	for i := 1; i <= 3; i++ {
		var ch Changes
		recs, ch = Update(recs, shopInventory("1.24.0"), at(i), notOld)
		if !ch.Empty() {
			t.Errorf("run %d: %+v", i, ch)
		}
	}
	if got := places(recs); !slices.Equal(got, []string{"shop.example.com:80", "shop.example.com:443"}) {
		t.Errorf("records %v", got)
	}
}

func TestGoneRecordsAreKeptForAYear(t *testing.T) {
	gone := at(0)
	recs := []Record{
		{Host: "shop.example.com", Port: 443, FirstSeen: at(0), LastSeen: at(0)},
		{Host: "old.example.com", Port: 443, FirstSeen: at(0), LastSeen: at(0), Missed: 2, Gone: &gone},
	}
	recs, _ = Update(recs, shopInventory("1.24.0"), at(399), everywhere)
	if len(recs) != 3 {
		t.Fatalf("records %v", places(recs))
	}
	recs, _ = Update(recs, shopInventory("1.24.0"), at(401), everywhere)
	if got := places(recs); !slices.Equal(got, []string{"shop.example.com:80", "shop.example.com:443"}) {
		t.Errorf("records %v", got)
	}
}

func TestChangesAdd(t *testing.T) {
	var c Changes
	c.Add(Changes{New: []Record{{Host: "a"}}})
	c.Add(Changes{Gone: []Gone{{Record: Record{Host: "b"}}}, Updated: []VersionChange{{Host: "c"}}})
	if c.Empty() || len(c.New) != 1 || len(c.Gone) != 1 || len(c.Updated) != 1 {
		t.Errorf("changes %+v", c)
	}
}

func TestChangesTrim(t *testing.T) {
	old, recent := at(0), at(100)
	var c Changes
	for i := range 5 {
		c.New = append(c.New, Record{Host: "h" + strconv.Itoa(i), LastSeen: recent})
	}
	c.New = append([]Record{{Host: "old", LastSeen: old}}, c.New...)
	c.Gone = []Gone{{Record: Record{Host: "old", Gone: &old}}, {Record: Record{Host: "new", Gone: &recent}}}
	c.Updated = []VersionChange{{Host: "old", At: old}, {Host: "new", At: recent}}
	c.Trim(at(100), 90*24*time.Hour, 3)
	if got := places(c.New); !slices.Equal(got, []string{"h2:0", "h3:0", "h4:0"}) {
		t.Errorf("new %v", got)
	}
	if len(c.Gone) != 1 || c.Gone[0].Host != "new" || len(c.Updated) != 1 || c.Updated[0].Host != "new" {
		t.Errorf("gone %+v, updated %+v", c.Gone, c.Updated)
	}
}

func eventKinds(r Record) []string {
	var out []string
	for _, e := range r.Events {
		out = append(out, e.Kind)
	}
	return out
}

func TestRecordKeepsEvents(t *testing.T) {
	old := Asset{Host: "old.example.com", Source: "ct", IPs: []string{"192.0.2.12"}, Services: []Service{
		{Port: 443, Technologies: []Technology{{ID: "grafana", Name: "Grafana", Version: "10.2.3"}}},
	}}
	recs, _ := Update(nil, shopInventory("1.24.0", old), at(0), everywhere)
	if len(recs[0].Events) != 0 {
		t.Fatalf("the first run logged %+v", recs[0].Events)
	}
	// nginx is upgraded on both ports of the shop.
	before := recs
	recs, _ = Update(recs, shopInventory("1.30.6", old), at(1), everywhere)
	shop := recs[2]
	if len(shop.Events) != 1 || shop.Events[0] != (Event{At: at(1), Kind: EventVersion, Product: "nginx", From: "1.24.0", To: "1.30.6"}) {
		t.Fatalf("version event %+v", shop.Events)
	}
	if len(before[2].Events) != 0 {
		t.Errorf("the records passed in were changed: %+v", before[2].Events)
	}
	// The old host goes away, and comes back with another version: the
	// version is not reported as an update, but the record keeps it.
	recs, _ = Update(recs, shopInventory("1.30.6"), at(2), everywhere)
	recs, _ = Update(recs, shopInventory("1.30.6"), at(3), everywhere)
	old.Services[0].Technologies[0].Version = "11.1.0"
	recs, ch := Update(recs, shopInventory("1.30.6", old), at(9), everywhere)
	if len(ch.Updated) != 0 {
		t.Errorf("a service that came back reported updates: %+v", ch.Updated)
	}
	got := recs[0]
	if kinds := eventKinds(got); !slices.Equal(kinds, []string{EventGone, EventBack, EventVersion}) {
		t.Fatalf("events %v", kinds)
	}
	if !got.Events[0].At.Equal(at(3)) || !got.Events[1].At.Equal(at(9)) || got.Events[2].To != "11.1.0" {
		t.Errorf("events %+v", got.Events)
	}
	// What the changes carry is the record with its events.
	if len(ch.New) != 1 || len(ch.New[0].Events) != 3 {
		t.Errorf("back %+v", ch.New)
	}
}

func TestRecordEventsAreCapped(t *testing.T) {
	recs, _ := Update(nil, shopInventory("1.0.0"), at(0), everywhere)
	for i := 1; i <= maxEvents+20; i++ {
		recs, _ = Update(recs, shopInventory("1.0."+strconv.Itoa(i)), at(i), everywhere)
	}
	evs := recs[0].Events
	if len(evs) != maxEvents || evs[0].To != "1.0.21" || evs[len(evs)-1].To != "1.0."+strconv.Itoa(maxEvents+20) {
		t.Errorf("%d events, from %q to %q", len(evs), evs[0].To, evs[len(evs)-1].To)
	}
}
