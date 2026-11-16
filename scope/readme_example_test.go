package scope

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestReadmeScopeExample keeps the scope file shown in the README valid.
func TestReadmeScopeExample(t *testing.T) {
	data, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "A scope file looks like this")
	if !ok {
		t.Fatal("the README no longer introduces the scope file")
	}
	_, rest, _ = strings.Cut(rest, "```json\n")
	example, _, ok := strings.Cut(rest, "```")
	if !ok {
		t.Fatal("no scope example in the README")
	}
	sc, err := Parse([]byte(example), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("the README's scope example is not valid: %v", err)
	}
	for host, want := range map[string]string{
		"shop.example.com":     "Web team",
		"api.shop.example.com": "Web team",
		"vpn.example.com":      "Network",
		"203.0.113.2":          "Network",
	} {
		if o := sc.OwnerOf(host); o == nil || o.Name != want {
			t.Errorf("owner of %s = %+v, want %s", host, o, want)
		}
	}
	if o := sc.OwnerOf("example.com"); o != nil {
		t.Errorf("owner of example.com = %+v, want none", o)
	}
}
