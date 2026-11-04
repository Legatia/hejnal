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

func TestExampleValidates(t *testing.T) {
	data, err := json.Marshal(Example(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, now); err != nil {
		t.Fatalf("example scope does not validate: %v", err)
	}
}
