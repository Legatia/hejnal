package scope

import (
	"testing"
	"time"
)

// Scopes come from customers; a malformed one must be refused, never crash.
func FuzzParse(f *testing.F) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	f.Add([]byte(`{"organization":"T","authorization":{"confirmedBy":"A","date":"2026-11-01","statement":"ok"},"domains":["example.com"],"hosts":["203.0.113.1"],"cidrs":["198.51.100.0/24"],"exclude":["dev.example.com"],"ports":[443]}`), "www.example.com")
	f.Add([]byte(`{"organization":"T","authorization":{"confirmedBy":"A","date":"2026-11-01","statement":"ok"},"cidrs":["0.0.0.0/0"]}`), "10.0.0.1")
	f.Fuzz(func(t *testing.T, data []byte, host string) {
		s, err := Parse(data, now)
		if err != nil {
			return
		}
		s.HostInScope(host)
		s.Explicit(host)
	})
}
