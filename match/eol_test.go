package match

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/eol"
	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/inventory"
)

func eolRun(t *testing.T, at time.Time, techs ...inventory.Technology) []Finding {
	t.Helper()
	cat, err := eol.Load("../testdata/eol_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := fingerprint.Default()
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{Assets: []inventory.Asset{{Host: "shop.example.com", Services: []inventory.Service{{
		Port: 443, Scheme: "https", URL: "https://shop.example.com/", Technologies: techs,
	}}}}}
	var out []Finding
	for _, f := range Run(inv, nil, eng, Options{Now: at, EOL: cat}) {
		if f.Kind == KindEOL {
			out = append(out, f)
		}
	}
	return out
}

func TestEndOfSupport(t *testing.T) {
	fs := eolRun(t, now,
		tech("nginx", "nginx", "server", "1.24.0", false),
		tech("php", "PHP", "language", "8.2.10", false),
		tech("tomcat", "Apache Tomcat", "server", "9.0.85", false),
		tech("wordpress", "WordPress", "cms", "6.4.3", false),
	)
	got := byKey(fs)
	if len(got) != 2 {
		t.Fatalf("%d findings, want nginx and PHP: %+v", len(got), fs)
	}
	// nginx 1.24 ended in April 2024: work for this month.
	n, ok := got["eol|shop.example.com|443|nginx|1.24"]
	if !ok {
		t.Fatalf("no nginx finding: %+v", fs)
	}
	if !n.SupportEnded || n.SupportEnds != "2024-04-23" || n.Release != "1.24" || n.Version != "1.24.0" ||
		n.Score != 55 || n.Severity != Medium || n.Confidence != ConfidenceObserved || n.Technology != "nginx" ||
		!slices.Equal(n.UpgradeTo, []string{"1.30.6", "1.31.8"}) || !slices.Equal(n.Links, []string{"https://endoflife.date/nginx"}) {
		t.Errorf("nginx finding %+v", n)
	}
	// PHP 8.2's support ends on 31 December 2026, within 90 days: work to
	// plan, listed with its date.
	p, ok := got["eol|shop.example.com|443|php|8.2"]
	if !ok {
		t.Fatalf("no PHP finding: %+v", fs)
	}
	if p.SupportEnded || p.SupportEnds != "2026-12-31" || p.Score != 30 || p.Severity != Low ||
		!slices.Equal(p.UpgradeTo, []string{"8.3.36", "8.5.12"}) {
		t.Errorf("PHP finding %+v", p)
	}
	// Tomcat 9.0's support ends in March 2027, beyond the window, and
	// WordPress 6.4 still gets fixes: neither is listed.
}

// The item stays the same from the warning until the upgrade: when the day
// comes, its severity rises, but it keeps its key, so it is not reported as
// fixed and found again.
func TestEndOfSupportKeepsItsKey(t *testing.T) {
	php := tech("php", "PHP", "language", "8.2.10", false)
	before := eolRun(t, now, php)
	after := eolRun(t, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC), php)
	if len(before) != 1 || len(after) != 1 || before[0].Key != after[0].Key {
		t.Fatalf("before %+v, after %+v", before, after)
	}
	if !after[0].SupportEnded || after[0].Severity != Medium {
		t.Errorf("after the end date: %+v", after[0])
	}
	// Upgrading within the release keeps the item; moving to another
	// release closes it.
	if fs := eolRun(t, now, tech("php", "PHP", "language", "8.2.29", false)); len(fs) != 1 || fs[0].Key != before[0].Key {
		t.Errorf("a patch release changed the item: %+v", fs)
	}
	if fs := eolRun(t, now, tech("php", "PHP", "language", "8.4.1", false)); len(fs) != 0 {
		t.Errorf("a supported release is still listed: %+v", fs)
	}
}

func TestEndOfSupportNeedsAnUpstreamVersion(t *testing.T) {
	packaged := tech("nginx", "nginx", "server", "1.18.0", false)
	packaged.Packaged = true
	static := tech("nginx", "nginx", "server", "1.18.0", false)
	static.Static = true
	for name, tc := range map[string]inventory.Technology{
		// A distribution keeps fixing its own nginx 1.18.
		"packaged":   packaged,
		"static":     static,
		"no version": tech("nginx", "nginx", "server", "", false),
		// IIS has no endoflife.date product.
		"no product": tech("iis", "Microsoft IIS", "server", "8.5", false),
		// No release of nginx is 0.1.
		"no release": tech("nginx", "nginx", "server", "0.1.2", false),
	} {
		if fs := eolRun(t, now, tc); len(fs) != 0 {
			t.Errorf("%s: %+v", name, fs)
		}
	}
	if fs := Run(&inventory.Inventory{}, nil, nil, Options{Now: now}); len(fs) != 0 {
		t.Errorf("findings without data: %+v", fs)
	}
}

func TestEndOfSupportOnDevices(t *testing.T) {
	// RouterOS is not in the sample, so build a catalog with it.
	cat, err := eol.Parse(strings.NewReader(`{"result": [{"name": "routeros", "releases": [
	  {"name": "7.25", "isEol": false, "latest": {"name": "7.25.1"}},
	  {"name": "6.48", "isEol": true, "eolFrom": "2023-01-01", "latest": {"name": "6.48.7"}}
	]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := fingerprint.Default()
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{Assets: []inventory.Asset{{Host: "gw.example.com", Services: []inventory.Service{{
		Port: 443, Scheme: "https", URL: "https://gw.example.com/",
		Technologies: []inventory.Technology{tech("mikrotik-routeros", "MikroTik RouterOS", "network", "6.48.6", true)},
	}}}}}
	var eolFindings []Finding
	for _, f := range Run(inv, nil, eng, Options{Now: now, EOL: cat}) {
		if f.Kind == KindEOL {
			eolFindings = append(eolFindings, f)
		}
	}
	if len(eolFindings) != 1 || eolFindings[0].Score != 65 || !slices.Equal(eolFindings[0].UpgradeTo, []string{"7.25.1"}) {
		t.Errorf("findings %+v", eolFindings)
	}
}
