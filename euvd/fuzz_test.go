package euvd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	if data, err := os.ReadFile(dumpSample); err == nil {
		f.Add(data)
	}
	f.Add([]byte(`[{"cveId":"CVE-2026-1","euvdId":"EUVD-2026-1","dateAdded":"2026-01-01","sources":["eukev_kev"],"vendorProject":"a\u0000b","product":"Various"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, e := range entries {
			if !cveRE.MatchString(e.CVEID) || !euvdRE.MatchString(e.EUVDID) || !dateRE.MatchString(e.DateAdded) {
				t.Fatalf("invalid entry kept: %+v", e)
			}
			for _, s := range []string{e.VendorProject, e.Product, e.VulnerabilityName} {
				if strings.ContainsAny(s, "\x00\r\n\t") || len(s) > maxField+len("…") {
					t.Fatalf("field not cleaned: %q", s)
				}
			}
		}
	})
}

func FuzzParseRecord(f *testing.F) {
	if data, err := os.ReadFile(recordSample); err == nil {
		f.Add(data)
	}
	f.Add([]byte(`{"id":"EUVD-2026-1","references":"javascript:x\nhttps://ok.example/a\"b"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := ParseRecord(bytes.NewReader(data))
		if err != nil {
			return
		}
		if !euvdRE.MatchString(rec.ID) || len(rec.Description) > maxDescription+len("…") {
			t.Fatalf("record not validated: %q, %d", rec.ID, len(rec.Description))
		}
		for _, u := range rec.References {
			if !SafeURL(u) {
				t.Fatalf("unsafe reference %q", u)
			}
		}
	})
}
