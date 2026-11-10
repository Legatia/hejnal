package scope

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

const auth = `"organization": "Przykład Sp. z o.o.",
  "authorization": {"confirmedBy": "Anna Nowak, IT", "date": "2026-11-01", "statement": "We own these systems."}`

const valid = `{
  ` + auth + `,
  "domains": ["Example.com."],
  "hosts": ["vpn.example.org", "198.51.100.7"],
  "cidrs": ["203.0.113.0/29"],
  "exclude": ["legacy.example.com", "203.0.113.4"],
  "ports": [443, 80, 443]
}`

func mustParse(t *testing.T, doc string) *Scope {
	t.Helper()
	s, err := Parse([]byte(doc), now)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestParseNormalises(t *testing.T) {
	s := mustParse(t, valid)
	if !slices.Equal(s.Domains, []string{"example.com"}) {
		t.Errorf("Domains = %v", s.Domains)
	}
	if !slices.Equal(s.Ports, []int{80, 443}) {
		t.Errorf("Ports = %v, want sorted and unique", s.Ports)
	}
	if n := len(s.Addresses()); n != 7 {
		t.Errorf("Addresses() = %d addresses, want 7 (8 in the range minus 1 excluded)", n)
	}
}

func TestDefaultPorts(t *testing.T) {
	s := mustParse(t, `{`+auth+`, "domains": ["example.com"]}`)
	if !slices.Equal(s.Ports, DefaultPorts) {
		t.Errorf("Ports = %v, want %v", s.Ports, DefaultPorts)
	}
}

func TestHostInScope(t *testing.T) {
	s := mustParse(t, valid)
	cases := map[string]bool{
		"example.com":          true,
		"EXAMPLE.COM.":         true,
		"www.example.com":      true,
		"a.b.example.com":      true,
		"legacy.example.com":   false,
		"x.legacy.example.com": false,
		"notexample.com":       false,
		"example.com.evil.net": false,
		"vpn.example.org":      true,
		"other.example.org":    false,
		"198.51.100.7":         true,
		"198.51.100.8":         false,
		"203.0.113.1":          true,
		"203.0.113.4":          false,
		"203.0.113.8":          false,
		"::ffff:203.0.113.1":   true,
		"[198.51.100.7]":       true,
		"":                     false,
	}
	for host, want := range cases {
		if got := s.HostInScope(host); got != want {
			t.Errorf("HostInScope(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestExplicitAndExcluded(t *testing.T) {
	s := mustParse(t, valid)
	for host, want := range map[string]bool{
		"vpn.example.org": true,
		"www.example.com": false,
		"example.com":     false,
		"203.0.113.2":     true,
		"203.0.113.4":     false,
	} {
		if got := s.Explicit(host); got != want {
			t.Errorf("Explicit(%q) = %v, want %v", host, got, want)
		}
	}
	if !s.IPExcluded(netip.MustParseAddr("203.0.113.4")) {
		t.Error("203.0.113.4 should be excluded")
	}
	if s.IPExcluded(netip.MustParseAddr("203.0.113.5")) {
		t.Error("203.0.113.5 should not be excluded")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{"no authorization", `{"organization": "X", "domains": ["example.com"]}`, "confirmedBy is required"},
		{"future date", `{"organization": "X", "authorization": {"confirmedBy": "A", "date": "2026-12-01", "statement": "ok"}, "domains": ["example.com"]}`, "in the future"},
		{"bad date", `{"organization": "X", "authorization": {"confirmedBy": "A", "date": "01.11.2026", "statement": "ok"}, "domains": ["example.com"]}`, "YYYY-MM-DD"},
		{"wildcard", `{` + auth + `, "domains": ["*.example.com"]}`, "wildcards are not allowed"},
		{"ip as domain", `{` + auth + `, "domains": ["203.0.113.1"]}`, "is an IP address"},
		{"no dot", `{` + auth + `, "domains": ["localhost"]}`, "must include a dot"},
		{"bad label", `{` + auth + `, "hosts": ["bad_name.example.com"]}`, "invalid label"},
		{"range too large", `{` + auth + `, "cidrs": ["10.0.0.0/16"]}`, "the limit is 1024"},
		{"bad cidr", `{` + auth + `, "cidrs": ["10.0.0.0/33"]}`, "cidr"},
		{"nothing to check", `{` + auth + `}`, "at least one domain"},
		{"bad port", `{` + auth + `, "domains": ["example.com"], "ports": [0]}`, "out of range"},
		{"unknown field", `{` + auth + `, "domain": ["example.com"]}`, "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc), now)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestHostInScopeRejectsOddNames(t *testing.T) {
	s := mustParse(t, valid)
	for _, h := range []string{
		"ｌｅｇａｃｙ.example.com", // full-width look-alike of an excluded name
		".example.com",
		"a..example.com",
		"under_score.example.com",
		"bad name.example.com",
		"fe80::1%eth0",
	} {
		if s.HostInScope(h) {
			t.Errorf("HostInScope(%q) = true, want false", h)
		}
	}
}

func TestNumericNamesAndZonesRejected(t *testing.T) {
	for doc, want := range map[string]string{
		`{` + auth + `, "domains": ["0.1"]}`:                                       "looks like an IP address",
		`{` + auth + `, "hosts": ["fe80::1%eth0"]}`:                                "zones",
		`{` + auth + `, "cidrs": ["::ffff:0:0/95"]}`:                               "must be /96 or longer",
		`{` + auth + `, "domains": ["example.com"], "exclude": ["::ffff:0:0/90"]}`: "must be /96 or longer",
	} {
		if _, err := Parse([]byte(doc), now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%s) error = %v, want %q", doc, err, want)
		}
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	s := mustParse(t, `{`+auth+`, "cidrs": ["::ffff:203.0.113.0/125"], "exclude": ["::ffff:203.0.113.4", "64:ff9b::cb00:7105"]}`)
	if n := len(s.Addresses()); n != 6 {
		t.Errorf("Addresses() = %d, want 6 (8 in the range minus 2 excluded)", n)
	}
	for addr, want := range map[string]bool{
		"203.0.113.1":        true,
		"203.0.113.4":        false,
		"203.0.113.5":        false,
		"::ffff:203.0.113.1": true,
		"64:ff9b::cb00:7101": true,  // NAT64 form of 203.0.113.1
		"64:ff9b::cb00:7104": false, // NAT64 form of an excluded address
		"203.0.113.9":        false,
	} {
		if got := s.IPInScope(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IPInScope(%s) = %v, want %v", addr, got, want)
		}
	}
	if got := Canonical(netip.MustParseAddr("64:ff9b::a00:1")); got != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("Canonical(64:ff9b::a00:1) = %s", got)
	}
}

func TestExampleValidates(t *testing.T) {
	data, err := json.Marshal(Example(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, now); err != nil {
		t.Fatalf("example scope does not validate: %v", err)
	}
}

func TestPlaceholders(t *testing.T) {
	// The example file as written: every entry is named.
	data, err := json.Marshal(Example(now))
	if err != nil {
		t.Fatal(err)
	}
	got := mustParse(t, string(data)).Placeholders()
	want := []string{
		`organization "Example Sp. z o.o."`,
		`authorization.confirmedBy "Jan Kowalski, IT manager"`,
		"domain example.com",
		"host vpn.example.com",
		"range 203.0.113.0/29",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Placeholders = %q\nwant %q", got, want)
	}

	// Documentation names and addresses on their own, in any spelling.
	got = mustParse(t, `{`+auth+`,
	  "domains": ["Shop.Example.ORG."],
	  "hosts": ["192.0.2.7", "2001:db8::1", "::ffff:198.51.100.9"],
	  "cidrs": ["2001:db8:1::/120", "192.0.2.128/25"]}`).Placeholders()
	want = []string{"domain shop.example.org", "host 192.0.2.7", "host 2001:db8::1", "host 198.51.100.9", "range 2001:db8:1::/120", "range 192.0.2.128/25"}
	if !slices.Equal(got, want) {
		t.Errorf("Placeholders = %q\nwant %q", got, want)
	}

	// A real scope has none, including names that only look similar.
	got = mustParse(t, `{`+auth+`,
	  "domains": ["sklep.pl", "example.pl", "myexample.com"],
	  "hosts": ["vpn.sklep.pl", "203.0.114.1"],
	  "cidrs": ["10.0.0.0/24"]}`).Placeholders()
	if len(got) != 0 {
		t.Errorf("Placeholders = %q for a real scope", got)
	}
}
