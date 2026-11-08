package kev

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A tampered or broken feed must not crash Hejnal, and the links it puts in
// reports must stay plain web addresses.
func FuzzParse(f *testing.F) {
	if data, err := os.ReadFile("../testdata/kev_sample.json"); err == nil {
		f.Add(data)
	}
	f.Add([]byte(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-2026-1","notes":"https://a.example/x; javascript:alert(1) <https://b.example>"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		cat, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, v := range cat.Vulnerabilities {
			for _, l := range v.Links() {
				if !strings.HasPrefix(l, "https://") && !strings.HasPrefix(l, "http://") || strings.ContainsAny(l, "<>\"' `\\") {
					t.Fatalf("unsafe link %q", l)
				}
			}
		}
	})
}
