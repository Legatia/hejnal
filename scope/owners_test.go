package scope

import (
	"strings"
	"testing"
)

const withOwners = `{
  ` + auth + `,
  "domains": ["example.com"],
  "cidrs": ["203.0.113.0/28"],
  "owners": [
    {"name": "IT", "github": "@anna-nowak", "systems": ["Example.com.", "203.0.113.0/28"]},
    {"name": "Web team", "systems": ["shop.example.com"]},
    {"github": "piotr", "systems": ["203.0.113.8/30", "203.0.113.2"]}
  ]
}`

func TestOwnerOf(t *testing.T) {
	s := mustParse(t, withOwners)
	cases := []struct{ host, want string }{
		{"example.com", "IT"},
		{"mail.example.com", "IT"},
		{"shop.example.com", "Web team"},
		{"Staging.Shop.example.com.", "Web team"},
		{"notexample.com", ""},
		{"203.0.113.1", "IT"},
		{"203.0.113.2", "@piotr"},
		{"203.0.113.9", "@piotr"},
		{"::ffff:203.0.113.9", "@piotr"},
		{"198.51.100.1", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := ""
		if o := s.OwnerOf(c.host); o != nil {
			got = o.Label()
		}
		if got != c.want {
			t.Errorf("OwnerOf(%q) = %q, want %q", c.host, got, c.want)
		}
	}
	if o := s.OwnerOf("example.com"); o.GitHub != "anna-nowak" {
		t.Errorf("github login = %q", o.GitHub)
	}
	if o := mustParse(t, valid).OwnerOf("example.com"); o != nil {
		t.Errorf("owner without owners = %+v", o)
	}
}

func TestOwnerErrors(t *testing.T) {
	cases := []struct{ name, owners, want string }{
		{"nobody", `[{"systems": ["example.com"]}]`, "needs a name or a github login"},
		{"no systems", `[{"name": "IT"}]`, "list the systems they look after"},
		{"bad login", `[{"github": "anna nowak", "systems": ["example.com"]}]`, "is not a GitHub login"},
		{"login with two hyphens", `[{"github": "anna--nowak", "systems": ["example.com"]}]`, "is not a GitHub login"},
		{"wildcard", `[{"name": "IT", "systems": ["*.example.com"]}]`, "wildcards are not allowed"},
		{"bad range", `[{"name": "IT", "systems": ["203.0.113.0/33"]}]`, `system "203.0.113.0/33"`},
		{"two lines", `[{"name": "IT\nteam", "systems": ["example.com"]}]`, "one line"},
		{"unknown field", `[{"name": "IT", "system": ["example.com"]}]`, "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(`{`+auth+`, "domains": ["example.com"], "owners": `+c.owners+`}`), now)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}
