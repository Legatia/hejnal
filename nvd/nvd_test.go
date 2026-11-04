package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The fixtures are real NVD records (configurations only), taken from the
// public NVD JSON feeds on 2026-11-04.
func load(t *testing.T, cve string) *Record {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", cve+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rec, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestCheckRealRecords(t *testing.T) {
	cases := []struct {
		cve, product, version string
		want                  Verdict
		platforms             []string
	}{
		// PHP memory corruption: affected below 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
		{"CVE-2026-109618", "php:php", "8.3.12", Affected, nil},
		{"CVE-2026-109618", "php:php", "8.3.36", NotAffected, nil},
		{"CVE-2026-109618", "php:php", "8.5.12", NotAffected, nil},
		{"CVE-2026-109618", "php:php", "7.4.33", Affected, nil},
		{"CVE-2026-109618", "php:php", "7.2.1", NotAffected, nil}, // range starts at 7.3.0
		// PHP-CGI argument injection: only on Windows.
		{"CVE-2024-4577", "php:php", "8.3.7", AffectedOnPlatform, []string{"microsoft:windows"}},
		{"CVE-2024-4577", "php:php", "8.3.8", NotAffected, nil},
		// WordPress: ranges per branch, including two-part bounds such as "4.7".
		{"CVE-2026-119977", "wordpress:wordpress", "6.8.1", Affected, nil},
		{"CVE-2026-119977", "wordpress:wordpress", "4.6", NotAffected, nil},
		// Jenkins: LTS and weekly lines both listed.
		{"CVE-2024-23897", "jenkins:jenkins", "2.426.2", Affected, nil},
		{"CVE-2024-23897", "jenkins:jenkins", "2.462.3", NotAffected, nil},
		{"CVE-2024-23897", "jenkins:jenkins", "2.441", Affected, nil},
		// Apache HTTP Server path traversal: exactly 2.4.49.
		{"CVE-2021-41773", "apache:http_server", "2.4.49", Affected, nil},
		{"CVE-2021-41773", "apache:http_server", "2.4.62", NotAffected, nil},
		// Tomcat: milestone entries cannot be compared and are skipped.
		{"CVE-2025-24813", "apache:tomcat", "9.0.98", Affected, nil},
		{"CVE-2025-24813", "apache:tomcat", "10.1.35", NotAffected, nil},
		// No data for the product, or no usable version.
		{"CVE-2026-109618", "wordpress:wordpress", "6.8.1", Unknown, nil},
		{"CVE-2026-109618", "php:php", "", Unknown, nil},
		{"CVE-2026-109618", "php:php", "latest", Unknown, nil},
	}
	for _, c := range cases {
		got, platforms := load(t, c.cve).Check([]string{c.product}, c.version)
		if got != c.want || !slices.Equal(platforms, c.platforms) {
			t.Errorf("%s %s %q = %s %v, want %s %v", c.cve, c.product, c.version, got, platforms, c.want, c.platforms)
		}
	}
}

func TestParseAPIResponse(t *testing.T) {
	data, err := os.ReadFile("testdata/CVE-2024-23897.json")
	if err != nil {
		t.Fatal(err)
	}
	var cve map[string]any
	if err := json.Unmarshal(data, &cve); err != nil {
		t.Fatal(err)
	}
	wrapped, _ := json.Marshal(map[string]any{"resultsPerPage": 1, "vulnerabilities": []any{map[string]any{"cve": cve}}})
	rec, err := Parse(strings.NewReader(string(wrapped)))
	if err != nil {
		t.Fatal(err)
	}
	if rec.CVE != "CVE-2024-23897" || len(rec.Matches) != 2 {
		t.Errorf("record = %+v", rec)
	}
	if _, err := Parse(strings.NewReader(`{"vulnerabilities": []}`)); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty response error = %v, want ErrNotFound", err)
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"8.3.12", "8.3.8", 1},
		{"6.8", "6.8.0", 0},
		{"2.462.3", "2.442", 1},
		{"10.1.0-rc1", "10.1.0", -1},
		{"v1.2", "1.2.0", 0},
		{"4.7", "4.10", -1},
	} {
		a, ok1 := ParseVersion(c.a)
		b, ok2 := ParseVersion(c.b)
		if !ok1 || !ok2 {
			t.Fatalf("could not parse %q or %q", c.a, c.b)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"", "latest", "1.x", "1234567890.1"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) succeeded", bad)
		}
	}
}

func TestParseCPEEscapes(t *testing.T) {
	c, ok := parseCPE(`cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*`)
	if !ok || c.product != "prod:uct" || c.version != "1.0" {
		t.Errorf("parseCPE = %+v %v", c, ok)
	}
}

func TestClient(t *testing.T) {
	data, _ := os.ReadFile("testdata/CVE-2021-41773.json")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("cveId") != "CVE-2021-41773" || r.Header.Get("apiKey") != "k" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Write(data)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k", UserAgent: "hejnal-test"}
	rec, err := c.Fetch(context.Background(), "CVE-2021-41773")
	if err != nil {
		t.Fatal(err)
	}
	if rec.CVE != "CVE-2021-41773" || rec.Fetched.IsZero() {
		t.Errorf("record = %+v", rec)
	}

	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusForbidden)
	}))
	defer limited.Close()
	c2 := &Client{HTTP: limited.Client(), BaseURL: limited.URL, APIKey: "k"}
	if _, err := c2.Fetch(context.Background(), "CVE-2021-41773"); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error = %v", err)
	}
}

func TestCache(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	rec := load(t, "CVE-2024-23897")
	rec.Fetched = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if err := c.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Get("cve-2024-23897")
	if !ok || len(got.Matches) != 2 {
		t.Fatalf("Get = %+v %v", got, ok)
	}
	if _, ok := c.Get("../../etc/passwd"); ok {
		t.Error("Get accepted a path instead of a CVE id")
	}
	if err := c.Put(&Record{CVE: "../x"}); err == nil {
		t.Error("Put accepted an invalid CVE id")
	}
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	if Stale(got, now) {
		t.Error("an analysed record three days old should not be stale")
	}
	if !Stale(&Record{CVE: "CVE-2026-0001", Fetched: now.Add(-48 * time.Hour)}, now) {
		t.Error("an unanalysed record two days old should be stale")
	}
}
