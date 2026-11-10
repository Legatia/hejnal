// Package osv matches packages against OSV (https://osv.dev), the open
// database of advisories for open-source packages and Linux distributions
// run by Google's Open Source Security Team.
//
// Only package names, ecosystems and versions are sent: never code, file
// names or anything about the project. Advisories are cached on disk and
// fetched again only when OSV says they changed.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultAPI is OSV's public API.
const DefaultAPI = "https://api.osv.dev"

// batchSize is how many packages go in one query. OSV pages results instead
// of refusing large batches; this keeps each request small.
const batchSize = 500

// Query is one package version to look up.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

// Vuln is an OSV advisory, with the fields Hejnal uses.
type Vuln struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary,omitempty"`
	Details   string    `json:"details,omitempty"`
	Aliases   []string  `json:"aliases,omitempty"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published,omitzero"`
	Withdrawn time.Time `json:"withdrawn,omitzero"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity,omitempty"`
	Affected []Affected `json:"affected,omitempty"`
	// DatabaseSpecific holds the source database's own fields, such as
	// GitHub's severity rating.
	DatabaseSpecific struct {
		Severity string `json:"severity,omitempty"`
	} `json:"database_specific"`
}

// Affected says which versions of one package an advisory covers.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
		} `json:"events"`
	} `json:"ranges,omitempty"`
	// EcosystemSpecific holds, for Ubuntu, the release's priority.
	EcosystemSpecific struct {
		Severity string `json:"severity,omitempty"`
	} `json:"ecosystem_specific"`
	DatabaseSpecific struct {
		Severity string `json:"severity,omitempty"`
	} `json:"database_specific"`
}

// CVEs returns the advisory's CVE IDs: its own, if it is one, and its
// aliases.
func (v *Vuln) CVEs() []string {
	var out []string
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if cveRE.MatchString(id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// Malicious reports whether the advisory is about malicious code, which
// OSV lists with MAL- IDs.
func (v *Vuln) Malicious() bool {
	if strings.HasPrefix(v.ID, "MAL-") {
		return true
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return false
}

// Rating returns the advisory's severity as its source rates it: critical,
// high, medium or low, or "" if it gives none.
func (v *Vuln) Rating(ecosystem, name string) string {
	for _, s := range []string{v.DatabaseSpecific.Severity} {
		if r := normRating(s); r != "" {
			return r
		}
	}
	for _, a := range v.Affected {
		if !samePackage(a.Package.Ecosystem, a.Package.Name, ecosystem, name) {
			continue
		}
		for _, s := range []string{a.DatabaseSpecific.Severity, a.EcosystemSpecific.Severity} {
			if r := normRating(s); r != "" {
				return r
			}
		}
	}
	for _, s := range v.Severity {
		if s.Type == "Ubuntu" {
			if r := normRating(s.Score); r != "" {
				return r
			}
		}
	}
	return ""
}

func normRating(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return ""
}

// samePackage compares an advisory's package with ours. Ecosystems match
// on their name before any ":release" suffix as well, because a Debian
// advisory names "Debian:12" while one for every release names "Debian".
func samePackage(eco, name, wantEco, wantName string) bool {
	if !strings.EqualFold(name, wantName) && !(strings.HasPrefix(wantEco, "PyPI") && normPy(name) == normPy(wantName)) {
		return false
	}
	if eco == wantEco {
		return true
	}
	base := func(e string) string { b, _, _ := strings.Cut(e, ":"); return b }
	return base(eco) == base(wantEco) && (!strings.Contains(eco, ":") || !strings.Contains(wantEco, ":"))
}

var pySep = regexp.MustCompile(`[-_.]+`)

func normPy(s string) string { return pySep.ReplaceAllString(strings.ToLower(s), "-") }

// FixedIn returns the first version that fixes the advisory for a package
// at version, or "" if the advisory names none.
func (v *Vuln) FixedIn(ecosystem, name, version string) string {
	var fixes []string
	for _, a := range v.Affected {
		if !samePackage(a.Package.Ecosystem, a.Package.Name, ecosystem, name) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixes = append(fixes, e.Fixed)
				}
			}
		}
	}
	// The fix for this version is the lowest fix above it; a fix on
	// another release line sorts below it and is skipped.
	slices.SortFunc(fixes, Compare)
	for _, f := range fixes {
		if Compare(f, version) > 0 {
			return f
		}
	}
	return ""
}

// Compare orders two versions by their numeric and text parts, which is
// right for semantic versions and close enough for other schemes to choose
// between fixes; matching itself is OSV's, which knows each ecosystem.
func Compare(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x == y {
			continue
		}
		xn, xok := num(x)
		yn, yok := num(y)
		switch {
		case xok && yok:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case x == "":
			// 1.0 is after 1.0-rc1 but before 1.0.1.
			if yok {
				return -1
			}
			return 1
		case y == "":
			if xok {
				return 1
			}
			return -1
		case xok:
			return 1
		case yok:
			return -1
		default:
			return strings.Compare(x, y)
		}
	}
	return 0
}

func versionParts(v string) []string {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, ':'); i >= 0 && i < 4 {
		v = v[i+1:] // a Debian epoch
	}
	var parts []string
	cur := ""
	digit := false
	flush := func() {
		if cur != "" {
			parts = append(parts, cur)
			cur = ""
		}
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if !digit {
				flush()
			}
			digit = true
			cur += string(r)
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			if digit {
				flush()
			}
			digit = false
			cur += string(r)
		default:
			flush()
			digit = false
		}
	}
	flush()
	return parts
}

func num(s string) (int, bool) {
	if s == "" || len(s) > 9 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

var (
	cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	idRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{2,79}$`)
)

// Client talks to OSV's API.
type Client struct {
	HTTP      *http.Client
	Base      string
	UserAgent string
	// CacheDir, if set, keeps advisories between runs.
	CacheDir string
}

func (c *Client) base() string {
	if c.Base == "" {
		return DefaultAPI
	}
	return strings.TrimSuffix(c.Base, "/")
}

func (c *Client) do(ctx context.Context, method, url string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("osv: %s %s: HTTP %d", method, strings.TrimPrefix(url, c.base()), resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// Hit is an advisory ID that covers a query, and when it last changed.
type Hit struct {
	ID       string
	Modified time.Time
}

// QueryBatch looks the packages up and returns, for each in order, the
// advisories that cover it.
func (c *Client) QueryBatch(ctx context.Context, qs []Query) ([][]Hit, error) {
	out := make([][]Hit, len(qs))
	for start := 0; start < len(qs); start += batchSize {
		end := min(start+batchSize, len(qs))
		pending := make([]int, 0, end-start)
		for i := start; i < end; i++ {
			pending = append(pending, i)
		}
		tokens := map[int]string{}
		for pages := 0; len(pending) > 0; pages++ {
			if pages > 20 {
				return nil, errors.New("osv: too many result pages")
			}
			type pkg struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}
			type query struct {
				Package   pkg    `json:"package"`
				Version   string `json:"version"`
				PageToken string `json:"page_token,omitempty"`
			}
			req := struct {
				Queries []query `json:"queries"`
			}{}
			for _, i := range pending {
				req.Queries = append(req.Queries, query{Package: pkg{qs[i].Name, qs[i].Ecosystem}, Version: qs[i].Version, PageToken: tokens[i]})
			}
			var resp struct {
				Results []struct {
					Vulns []struct {
						ID       string    `json:"id"`
						Modified time.Time `json:"modified"`
					} `json:"vulns"`
					NextPageToken string `json:"next_page_token"`
				} `json:"results"`
			}
			if err := c.do(ctx, http.MethodPost, c.base()+"/v1/querybatch", req, &resp); err != nil {
				return nil, err
			}
			if len(resp.Results) != len(pending) {
				return nil, fmt.Errorf("osv: %d results for %d queries", len(resp.Results), len(pending))
			}
			var next []int
			for j, r := range resp.Results {
				i := pending[j]
				for _, v := range r.Vulns {
					if idRE.MatchString(v.ID) {
						out[i] = append(out[i], Hit{v.ID, v.Modified})
					}
				}
				if r.NextPageToken != "" {
					tokens[i] = r.NextPageToken
					next = append(next, i)
				}
			}
			pending = next
		}
	}
	return out, nil
}

// Vuln returns an advisory, from the cache if it is no older than modified.
func (c *Client) Vuln(ctx context.Context, id string, modified time.Time) (*Vuln, error) {
	if !idRE.MatchString(id) {
		return nil, fmt.Errorf("osv: invalid ID %q", id)
	}
	path := ""
	if c.CacheDir != "" {
		path = filepath.Join(c.CacheDir, id+".json")
		if data, err := os.ReadFile(path); err == nil {
			var v Vuln
			if json.Unmarshal(data, &v) == nil && v.ID == id && !v.Modified.Before(modified) {
				return &v, nil
			}
		}
	}
	var v Vuln
	if err := c.do(ctx, http.MethodGet, c.base()+"/v1/vulns/"+id, nil, &v); err != nil {
		return nil, err
	}
	if v.ID != id {
		return nil, fmt.Errorf("osv: asked for %s, got %q", id, v.ID)
	}
	if len(v.Details) > 4000 {
		v.Details = v.Details[:4000]
	}
	if path != "" {
		if err := os.MkdirAll(c.CacheDir, 0o700); err == nil {
			if data, err := json.Marshal(&v); err == nil {
				tmp := path + ".tmp"
				if os.WriteFile(tmp, data, 0o600) == nil {
					os.Rename(tmp, path)
				}
			}
		}
	}
	return &v, nil
}

// Match is one advisory that covers one queried package.
type Match struct {
	Query Query
	Vuln  *Vuln
}

// fetchers is how many advisories Lookup downloads at once. A Debian or
// Ubuntu image can match thousands, and one at a time that adds minutes to
// a build with an empty cache.
const fetchers = 8

// Lookup finds the advisories covering each package, fetching each
// advisory once. Withdrawn advisories are left out.
func (c *Client) Lookup(ctx context.Context, qs []Query) ([]Match, error) {
	hits, err := c.QueryBatch(ctx, qs)
	if err != nil {
		return nil, err
	}
	// Each advisory once, as of the newest change any query reported.
	newest := map[string]time.Time{}
	var ids []string
	for _, hs := range hits {
		for _, h := range hs {
			t, seen := newest[h.ID]
			if !seen {
				ids = append(ids, h.ID)
			}
			if !seen || h.Modified.After(t) {
				newest[h.ID] = h.Modified
			}
		}
	}
	vulns, err := c.fetch(ctx, ids, newest)
	if err != nil {
		return nil, err
	}
	var out []Match
	for i, hs := range hits {
		for _, h := range hs {
			if v := vulns[h.ID]; v.Withdrawn.IsZero() {
				out = append(out, Match{Query: qs[i], Vuln: v})
			}
		}
	}
	return out, nil
}

// fetch downloads the advisories, several at once. The first error stops
// the rest.
func (c *Client) fetch(ctx context.Context, ids []string, modified map[string]time.Time) (map[string]*Vuln, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	got := make([]*Vuln, len(ids))
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)
	next := make(chan int)
	for range min(fetchers, len(ids)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				v, err := c.Vuln(ctx, ids[i], modified[ids[i]])
				if err != nil {
					once.Do(func() { first = err; cancel() })
					continue
				}
				got[i] = v
			}
		}()
	}
feed:
	for i := range ids {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if first == nil {
		first = ctx.Err() // the caller gave up
	}
	if first != nil {
		return nil, first
	}
	out := make(map[string]*Vuln, len(ids))
	for i, id := range ids {
		out[id] = got[i]
	}
	return out, nil
}
