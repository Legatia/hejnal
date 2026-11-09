package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.10", -1}, {"1.10.0", "1.9.9", 1}, {"1.0.0", "1.0.0", 0}, {"v1.2.3", "1.2.3", 0},
		{"1.0.0-rc1", "1.0.0", -1}, {"1.0.0", "1.0.0.1", -1}, {"2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"1:2.0", "1.9", 1}, {"4.17.20", "4.17.21", -1}, {"3.2.0", "3.2", 1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func vuln(t *testing.T, raw string) *Vuln {
	var v Vuln
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestFixedInAndRating(t *testing.T) {
	v := vuln(t, `{"id":"GHSA-x","aliases":["CVE-2021-23337"],"modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]},
		{"package":{"ecosystem":"npm","name":"lodash-es"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.30"}]}]}]}`)
	if got := v.FixedIn("npm", "lodash", "4.17.20"); got != "4.17.21" {
		t.Errorf("FixedIn = %q", got)
	}
	if v.Rating("npm", "lodash") != "high" || fmt.Sprint(v.CVEs()) != "[CVE-2021-23337]" || v.Malicious() {
		t.Errorf("rating %q, CVEs %v", v.Rating("npm", "lodash"), v.CVEs())
	}
	// Two release lines: the fix for 2.x is on 2.x.
	two := vuln(t, `{"id":"GHSA-y","modified":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"Django"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.2.24"},{"introduced":"3.0"},{"fixed":"3.1.12"},{"introduced":"3.2"},{"fixed":"3.2.4"}]}]}]}`)
	if got := two.FixedIn("PyPI", "django", "3.2.0"); got != "3.2.4" {
		t.Errorf("Django = %q", got)
	}
	deb := vuln(t, `{"id":"DSA-1","modified":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]}]}`)
	if got := deb.FixedIn("Debian:12", "openssl", "3.0.9-1"); got != "3.0.11-1~deb12u2" {
		t.Errorf("Debian = %q", got)
	}
	if got := deb.FixedIn("Debian:11", "openssl", "1.1.1n-0"); got != "" {
		t.Errorf("another release's fix: %q", got)
	}
	mal := vuln(t, `{"id":"MAL-2024-1","summary":"Malicious code in evil (npm)","modified":"2024-01-01T00:00:00Z"}`)
	if !mal.Malicious() {
		t.Error("MAL- advisory not malicious")
	}
}

func TestLookup(t *testing.T) {
	var batches, gets atomic.Int32
	mod := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			batches.Add(1)
			var req struct {
				Queries []struct {
					Package   struct{ Name, Ecosystem string }
					Version   string
					PageToken string `json:"page_token"`
				}
			}
			json.NewDecoder(r.Body).Decode(&req)
			var res []map[string]any
			for _, q := range req.Queries {
				switch {
				case q.Package.Name == "lodash" && q.PageToken == "":
					res = append(res, map[string]any{"vulns": []map[string]any{{"id": "GHSA-a", "modified": mod}}, "next_page_token": "p2"})
				case q.Package.Name == "lodash":
					res = append(res, map[string]any{"vulns": []map[string]any{{"id": "GHSA-gone", "modified": mod}, {"id": "../etc/passwd", "modified": mod}}})
				case q.Package.Name == "minimist":
					res = append(res, map[string]any{"vulns": []map[string]any{{"id": "GHSA-a", "modified": mod}}})
				default:
					res = append(res, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/vulns/GHSA-a":
			gets.Add(1)
			fmt.Fprintf(w, `{"id":"GHSA-a","modified":%q,"summary":"Prototype pollution"}`, mod.Format(time.RFC3339))
		case r.URL.Path == "/v1/vulns/GHSA-gone":
			gets.Add(1)
			fmt.Fprintf(w, `{"id":"GHSA-gone","modified":%q,"withdrawn":%q}`, mod.Format(time.RFC3339), mod.Format(time.RFC3339))
		default:
			w.WriteHeader(404)
			io.WriteString(w, "{}")
		}
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, CacheDir: t.TempDir()}
	qs := []Query{{"npm", "lodash", "4.17.20"}, {"npm", "minimist", "1.2.5"}, {"npm", "react", "18.2.0"}}
	ms, err := c.Lookup(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Query.Name != "lodash" || ms[1].Query.Name != "minimist" || ms[0].Vuln != ms[1].Vuln {
		t.Fatalf("matches = %+v", ms)
	}
	if batches.Load() != 2 || gets.Load() != 2 {
		t.Errorf("%d batches, %d advisory fetches", batches.Load(), gets.Load())
	}
	// The cache serves advisories that did not change.
	c2 := &Client{Base: srv.URL, CacheDir: c.CacheDir}
	if _, err := c2.Lookup(context.Background(), qs); err != nil || gets.Load() != 2 {
		t.Errorf("cache not used: %d fetches, %v", gets.Load(), err)
	}
	if _, err := c.Vuln(context.Background(), "../x", mod); err == nil {
		t.Error("a path as an ID was fetched")
	}
}
