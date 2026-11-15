package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const sample = "../testdata/eol_sample.json"

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func load(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load(sample)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func product(t *testing.T, c *Catalog, name string) *Product {
	t.Helper()
	p, ok := c.Product(name)
	if !ok {
		t.Fatalf("no product %q", name)
	}
	return p
}

func TestParseSample(t *testing.T) {
	c := load(t)
	if c.Generated != "2026-11-14" {
		t.Errorf("generated %q", c.Generated)
	}
	if c.Products() != 7 {
		t.Errorf("%d products, want 7", c.Products())
	}
	p := product(t, c, "nginx")
	if p.Link() != "https://endoflife.date/nginx" {
		t.Errorf("link %q", p.Link())
	}
	r, ok := p.Release("1.24.0")
	if !ok || r.Name != "1.24" || r.EOL != "2024-04-23" || !r.Ended || r.Latest != "1.24.0" {
		t.Errorf("release %+v %v", r, ok)
	}
}

func TestRelease(t *testing.T) {
	c := load(t)
	for _, tc := range []struct{ product, version, want string }{
		{"nginx", "1.24.0", "1.24"},
		{"nginx", "1.24", "1.24"},
		{"nginx", "1.240.1", ""}, // not 1.24
		{"nginx", "1.2", ""},
		{"nginx", "1.31.8", "1.31"},
		{"tomcat", "8.5.100", "8.5"},
		{"tomcat", "5.5.36", "5"},
		{"tomcat", "9.0.85", "9.0"},
		{"exim", "4.100.1", "4.100"},
		{"exim", "4.99", "4.99"},
		{"exim", "4.9", ""},
		// Jenkins' weekly line is release 2; its LTS lines have their own.
		{"jenkins", "2.590", "2"},
		{"jenkins", "2.555.3", "2.555"},
		{"drupal", "7.103", "7"},
		{"php", "8.1.2RC1", "8.1"},
		{"php", "", ""},
		{"php", "x8.1", ""},
	} {
		r, ok := product(t, c, tc.product).Release(tc.version)
		if ok != (tc.want != "") || r.Name != tc.want {
			t.Errorf("%s %q: got %q (%v), want %q", tc.product, tc.version, r.Name, ok, tc.want)
		}
	}
}

func TestEndedAt(t *testing.T) {
	c := load(t)
	for _, tc := range []struct {
		product, version string
		ended            bool
	}{
		{"nginx", "1.24.0", true},
		{"nginx", "1.30.6", false},
		{"php", "8.1.2", true},
		{"php", "8.2.1", false}, // ends on 31 Dec 2026
		{"jenkins", "2.555.1", true},
		{"wordpress", "6.4.3", false},
	} {
		r, _ := product(t, c, tc.product).Release(tc.version)
		if got := r.EndedAt(now); got != tc.ended {
			t.Errorf("%s %s ended %v, want %v", tc.product, tc.version, got, tc.ended)
		}
	}
	// The end date counts, not when endoflife.date generated the data.
	r := Release{Name: "8.2", EOL: "2026-12-31"}
	if r.EndedAt(time.Date(2026, 12, 30, 23, 0, 0, 0, time.UTC)) || !r.EndedAt(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Error("support ends on its end date")
	}
	// Without a date, endoflife.date's mark decides.
	if !(Release{Name: "1.0", Ended: true}).EndedAt(now) || (Release{Name: "1.0"}).EndedAt(now) {
		t.Error("a release without a date has ended only when marked so")
	}
}

func TestUpgrades(t *testing.T) {
	c := load(t)
	keep := 90 * 24 * time.Hour
	for _, tc := range []struct {
		product, version string
		want             []string
	}{
		// 1.30 is the closest supported release, 1.31 the newest; 1.29 and
		// 1.28 have ended.
		{"nginx", "1.24.0", []string{"1.30.6", "1.31.8"}},
		// 8.2's support ends within 90 days, so 8.3 is the closest.
		{"php", "8.1.2", []string{"8.3.36", "8.5.12"}},
		{"tomcat", "8.5.100", []string{"9.0.124", "11.0.29"}},
		// The weekly line is not newer than an LTS line.
		{"jenkins", "2.555.3", []string{"2.568.3"}},
		{"nginx", "1.31.8", nil},
		// Drupal 11.4 is the only newer release that lasts 90 days.
		{"drupal", "11.2.3", []string{"11.4.12"}},
	} {
		p := product(t, c, tc.product)
		r, _ := p.Release(tc.version)
		if got := p.Upgrades(r, now, keep); !slices.Equal(got, tc.want) {
			t.Errorf("%s %s: upgrades %v, want %v", tc.product, tc.version, got, tc.want)
		}
	}
}

func TestCompareNames(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.24", "1.3", 1, true},
		{"1.3", "1.24", -1, true},
		{"2", "2.555", -1, true},
		{"10.1", "10.1", 0, true},
		{"11.0", "9.0", 1, true},
		{"1.x", "1.2", 0, false},
		{"+1", "1", 0, false},
		{"1..2", "1.2", 0, false},
	} {
		got, ok := compareNames(tc.a, tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("compare(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

// Names, versions and dates from the feed end up in reports as they are, so
// anything that does not look like one is dropped or cleared.
func TestParseDropsWhatDoesNotLookRight(t *testing.T) {
	doc := `{"generated_at": "<b>", "result": [
	  {"name": "Bad Name", "releases": [{"name": "1.0", "isEol": true}]},
	  {"name": "ok", "releases": [
	    {"name": "1.0 <script>", "isEol": true},
	    {"name": "2.0", "isEol": true, "eolFrom": "2026-02-30", "latest": {"name": "2.0.1](https://evil.example)"}},
	    {"name": "3.0", "isEol": false, "eolFrom": "2027-01-01", "latest": {"name": "3.0.4"}}
	  ]},
	  {"name": "empty", "releases": []}
	]}`
	c, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if c.Generated != "" || c.Products() != 1 {
		t.Fatalf("generated %q, %d products", c.Generated, c.Products())
	}
	p := product(t, c, "ok")
	want := []Release{{Name: "2.0", Ended: true}, {Name: "3.0", EOL: "2027-01-01", Latest: "3.0.4"}}
	if !slices.Equal(p.Releases, want) {
		t.Errorf("releases %+v, want %+v", p.Releases, want)
	}
	if _, err := Parse(strings.NewReader(`{"result": []}`)); err == nil {
		t.Error("a document without products must fail")
	}
	if _, err := Parse(strings.NewReader(`[`)); err == nil {
		t.Error("broken JSON must fail")
	}
}

func TestFetchKeepsTheDocument(t *testing.T) {
	data, err := os.ReadFile(sample)
	if err != nil {
		t.Fatal(err)
	}
	var agent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent = r.UserAgent()
		if r.URL.Path != "/full" {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "cache", "eol.json")
	c, err := Fetch(context.Background(), srv.Client(), srv.URL+"/full", "hejnal-test", dest)
	if err != nil {
		t.Fatal(err)
	}
	if c.Products() != 7 || agent != "hejnal-test" {
		t.Errorf("%d products, user agent %q", c.Products(), agent)
	}
	if saved, err := os.ReadFile(dest); err != nil || string(saved) != string(data) {
		t.Errorf("cache not written: %v", err)
	}
	// A failed download leaves the cache alone.
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL+"/missing", "hejnal-test", dest); err == nil {
		t.Error("a 404 must fail")
	}
	if saved, _ := os.ReadFile(dest); string(saved) != string(data) {
		t.Error("a failed download changed the cache")
	}
}
