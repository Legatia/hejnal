package eol

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// A tampered or broken document must not crash Hejnal, and what it puts in
// reports must stay plain names, versions and dates.
func FuzzParse(f *testing.F) {
	if data, err := os.ReadFile("../testdata/eol_sample.json"); err == nil {
		f.Add(data, "1.24.0")
	}
	f.Add([]byte(`{"result":[{"name":"x","releases":[{"name":"1","isEol":true,"eolFrom":"2020-01-01","latest":{"name":"1.0.1"}}]}]}`), "1.0")
	f.Fuzz(func(t *testing.T, data []byte, version string) {
		c, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		at := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
		for _, p := range c.products {
			if !productRE.MatchString(p.Name) {
				t.Fatalf("product name %q", p.Name)
			}
			for _, r := range p.Releases {
				if !nameRE.MatchString(r.Name) || r.Latest != "" && !nameRE.MatchString(r.Latest) || r.EOL != "" && !validDate(r.EOL) {
					t.Fatalf("release %+v", r)
				}
			}
			r, ok := p.Release(version)
			if !ok {
				continue
			}
			for _, v := range p.Upgrades(r, at, 90*24*time.Hour) {
				if !nameRE.MatchString(v) {
					t.Fatalf("upgrade %q", v)
				}
			}
		}
	})
}
