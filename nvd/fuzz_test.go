package nvd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// NVD records decide whether a version is affected; a malformed one must
// not crash Hejnal or call every version affected by accident.
func FuzzParseAndCheck(f *testing.F) {
	files, _ := filepath.Glob("testdata/*.json")
	for _, name := range files {
		if data, err := os.ReadFile(name); err == nil {
			f.Add(data, "2.4.49", "cpe:2.3:a:apache:http_server")
		}
	}
	f.Add([]byte(`{}`), "", "")
	f.Fuzz(func(t *testing.T, data []byte, version, product string) {
		rec, err := Parse(bytes.NewReader(data))
		if err != nil || rec == nil {
			return
		}
		rec.Check([]string{product}, version, "")
	})
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"2.4.49", "7.20.1", "1.0.0-rc1", "10.0.17763.1", "", "...", "1..2", "v1.2"} {
		f.Add(s, "2.4.50")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		va, oka := ParseVersion(a)
		vb, okb := ParseVersion(b)
		if !oka || !okb {
			return
		}
		// Comparison must be consistent both ways.
		if c, d := va.Compare(vb), vb.Compare(va); c != -d {
			t.Fatalf("Compare(%q, %q) = %d but Compare(%q, %q) = %d", a, b, c, b, a, d)
		}
		if va.Compare(va) != 0 {
			t.Fatalf("%q does not equal itself", a)
		}
	})
}
