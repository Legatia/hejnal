package leaks

import (
	"strings"
	"testing"
)

// Repositories are scanned as they are, and so are the scripts of scanned
// sites; any content must scan without a crash, and a reported secret must
// stay redacted. CompleteKeys only ever leaves keys out.
func FuzzScanReader(f *testing.F) {
	f.Add("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	f.Add("token: ghp_" + strings.Repeat("a", 36) + "\n\x00\xff")
	f.Add("-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----")
	f.Add("x=\"-----BEGIN EC PRIVATE KEY-----\\nMC8CAQEEIGxh\\nAg==\\n-----END EC PRIVATE KEY-----\";")
	f.Fuzz(func(t *testing.T, content string) {
		found, err := ScanReader("file.txt", strings.NewReader(content), Options{})
		if err != nil {
			return
		}
		for _, l := range found {
			if len(l.Redacted) > 80 {
				t.Fatalf("redaction too long: %q", l.Redacted)
			}
		}
		complete, _ := ScanReader("file.txt", strings.NewReader(content), Options{CompleteKeys: true})
		if len(complete) > len(found) {
			t.Fatalf("CompleteKeys found more: %+v, %+v", complete, found)
		}
	})
}
