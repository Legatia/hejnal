// Package nvd reads affected-version data from the US National Vulnerability
// Database (NVD) and decides whether a product version is affected by a
// flaw.
//
// CISA's catalog says which product a flaw is in, but not which versions.
// NVD's analysts record that as CPE configurations: product names with
// version ranges, sometimes combined with a platform the flaw needs (for
// example "only on Windows"). New flaws are often not analysed yet; then
// there is no answer and Hejnal keeps the product-level finding.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultAPI is NVD's CVE API 2.0.
const DefaultAPI = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// ErrNotFound is returned by Parse when a response holds no CVE.
var ErrNotFound = errors.New("nvd: CVE not found")

// Match is one vulnerable product entry from NVD.
type Match struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	// Version is set when the entry names one exact version.
	Version string `json:"version,omitempty"`
	// Update qualifies an exact version, such as "milestone1".
	Update         string `json:"update,omitempty"`
	StartIncluding string `json:"startIncluding,omitempty"`
	StartExcluding string `json:"startExcluding,omitempty"`
	EndIncluding   string `json:"endIncluding,omitempty"`
	EndExcluding   string `json:"endExcluding,omitempty"`
	// Platforms lists vendor:product names the flaw also needs, from
	// configurations that combine the product with a platform.
	Platforms []string `json:"platforms,omitempty"`
}

// Record is what Hejnal keeps about one CVE.
type Record struct {
	CVE string `json:"cve"`
	// Status is NVD's analysis status, such as "Analyzed" or "Awaiting Analysis".
	Status  string    `json:"status,omitempty"`
	Matches []Match   `json:"matches,omitempty"`
	Fetched time.Time `json:"fetched"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type cveObject struct {
	ID             string `json:"id"`
	VulnStatus     string `json:"vulnStatus"`
	Configurations []struct {
		Operator string `json:"operator"`
		Nodes    []struct {
			Operator string     `json:"operator"`
			Negate   bool       `json:"negate"`
			CPEMatch []cpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// Parse reads an NVD API 2.0 response for one CVE, or a bare CVE object as
// published in NVD's data feeds.
func Parse(r io.Reader) (*Record, error) {
	var doc struct {
		cveObject
		Vulnerabilities []struct {
			CVE cveObject `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 16<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("nvd: decode: %w", err)
	}
	obj := doc.cveObject
	if len(doc.Vulnerabilities) > 0 {
		obj = doc.Vulnerabilities[0].CVE
	}
	if obj.ID == "" {
		return nil, ErrNotFound
	}
	rec := &Record{CVE: strings.ToUpper(obj.ID), Status: obj.VulnStatus}
	for _, cfg := range obj.Configurations {
		// Platforms the configuration requires besides the vulnerable product.
		var platforms []string
		if strings.EqualFold(cfg.Operator, "AND") {
			for _, n := range cfg.Nodes {
				for _, m := range n.CPEMatch {
					if !m.Vulnerable {
						if c, ok := parseCPE(m.Criteria); ok {
							platforms = append(platforms, c.vendor+":"+c.product)
						}
					}
				}
			}
			slices.Sort(platforms)
			platforms = slices.Compact(platforms)
		}
		for _, n := range cfg.Nodes {
			if n.Negate {
				continue
			}
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				c, ok := parseCPE(m.Criteria)
				if !ok {
					continue
				}
				mt := Match{
					Vendor:         c.vendor,
					Product:        c.product,
					StartIncluding: m.VersionStartIncluding,
					StartExcluding: m.VersionStartExcluding,
					EndIncluding:   m.VersionEndIncluding,
					EndExcluding:   m.VersionEndExcluding,
					Platforms:      platforms,
				}
				if c.version != "*" && c.version != "-" && c.version != "" {
					mt.Version = c.version
					if c.update != "*" && c.update != "-" {
						mt.Update = c.update
					}
				}
				rec.Matches = append(rec.Matches, mt)
			}
		}
	}
	return rec, nil
}

type cpe struct{ vendor, product, version, update string }

// parseCPE splits a CPE 2.3 formatted string, honouring backslash escapes.
func parseCPE(s string) (cpe, bool) {
	var fields []string
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			fields = append(fields, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	fields = append(fields, b.String())
	if len(fields) < 7 || fields[0] != "cpe" || fields[1] != "2.3" {
		return cpe{}, false
	}
	return cpe{
		vendor:  strings.ToLower(fields[3]),
		product: strings.ToLower(fields[4]),
		version: strings.ToLower(fields[5]),
		update:  strings.ToLower(fields[6]),
	}, true
}

// Verdict is the answer to "is this version affected?".
type Verdict int

// Verdicts.
const (
	// Unknown: NVD has no usable data for this product, or the version
	// cannot be compared.
	Unknown Verdict = iota
	// Affected: the version is in an affected range.
	Affected
	// AffectedOnPlatform: the version is affected, but only together with
	// a platform Hejnal cannot see, such as a particular operating system.
	AffectedOnPlatform
	// NotAffected: NVD lists affected versions of this product, and this
	// version is not among them.
	NotAffected
)

func (v Verdict) String() string {
	return [...]string{"unknown", "affected", "affected-on-platform", "not-affected"}[v]
}

// Check decides whether version of any of the products (vendor:product
// names) is affected. For AffectedOnPlatform it also returns the platforms.
func (r *Record) Check(products []string, version string) (Verdict, []string) {
	if r == nil || version == "" {
		return Unknown, nil
	}
	v, ok := ParseVersion(version)
	if !ok {
		return Unknown, nil
	}
	applicable, affected := false, false
	var platforms []string
	for _, m := range r.Matches {
		if !slices.Contains(products, m.Vendor+":"+m.Product) {
			continue
		}
		hit := false
		switch {
		case m.Version != "":
			if m.Update != "" {
				continue // a pre-release or patch qualifier Hejnal cannot see
			}
			exact, ok := ParseVersion(m.Version)
			if !ok {
				continue
			}
			applicable = true
			hit = v.Compare(exact) == 0
		default:
			in, ok := inRange(v, m)
			if !ok {
				continue
			}
			applicable = true
			hit = in
		}
		if !hit {
			continue
		}
		if len(m.Platforms) > 0 {
			platforms = append(platforms, m.Platforms...)
		} else {
			affected = true
		}
	}
	switch {
	case affected:
		return Affected, nil
	case len(platforms) > 0:
		slices.Sort(platforms)
		return AffectedOnPlatform, slices.Compact(platforms)
	case applicable:
		return NotAffected, nil
	}
	return Unknown, nil
}

// inRange reports whether v is inside the match's range. ok is false when a
// bound cannot be parsed. A match with no bounds at all covers every version.
func inRange(v Version, m Match) (in, ok bool) {
	check := func(bound string, accept func(int) bool) (bool, bool) {
		if bound == "" {
			return true, true
		}
		b, ok := ParseVersion(bound)
		if !ok {
			return false, false
		}
		return accept(v.Compare(b)), true
	}
	for _, c := range []struct {
		bound  string
		accept func(int) bool
	}{
		{m.StartIncluding, func(c int) bool { return c >= 0 }},
		{m.StartExcluding, func(c int) bool { return c > 0 }},
		{m.EndIncluding, func(c int) bool { return c <= 0 }},
		{m.EndExcluding, func(c int) bool { return c < 0 }},
	} {
		in, ok := check(c.bound, c.accept)
		if !ok {
			return false, false
		}
		if !in {
			return false, true
		}
	}
	return true, true
}

// Version is a dotted numeric version with an optional pre-release suffix.
type Version struct {
	nums []int
	pre  string
}

var versionRE = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)(?:[-_.~+]?((?:alpha|beta|rc|preview|pre|dev|snapshot|milestone|m|a|b)[0-9.]*))?$`)

// ParseVersion reads versions such as "8.3.12", "6.8", "2.462.3" or
// "10.1.0-rc1". Missing components count as zero, so "6.8" equals "6.8.0".
func ParseVersion(s string) (Version, bool) {
	m := versionRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return Version{}, false
	}
	var v Version
	for _, p := range strings.Split(m[1], ".") {
		if len(p) > 9 {
			return Version{}, false
		}
		n := 0
		for _, d := range p {
			n = n*10 + int(d-'0')
		}
		v.nums = append(v.nums, n)
	}
	v.pre = m[2]
	return v, true
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release.
func (v Version) Compare(o Version) int {
	for i := 0; i < max(len(v.nums), len(o.nums)); i++ {
		a, b := 0, 0
		if i < len(v.nums) {
			a = v.nums[i]
		}
		if i < len(o.nums) {
			b = o.nums[i]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.pre == o.pre:
		return 0
	case v.pre == "":
		return 1
	case o.pre == "":
		return -1
	}
	return strings.Compare(v.pre, o.pre)
}

// Client fetches CVE records from the NVD API, pacing requests to stay
// within NVD's public rate limits.
type Client struct {
	HTTP      *http.Client
	BaseURL   string
	APIKey    string
	UserAgent string
	// Pause overrides the pause between requests (for tests).
	Pause time.Duration

	mu   sync.Mutex
	last time.Time
}

// Interval is the pause between requests: NVD allows 5 requests per 30
// seconds without an API key and 50 with one.
func (c *Client) Interval() time.Duration {
	if c.Pause > 0 {
		return c.Pause
	}
	if c.APIKey != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

// Fetch downloads one CVE record.
func (c *Client) Fetch(ctx context.Context, cve string) (*Record, error) {
	c.mu.Lock()
	wait := time.Until(c.last.Add(c.Interval()))
	c.mu.Unlock()
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	c.mu.Lock()
	c.last = time.Now()
	c.mu.Unlock()

	base := c.BaseURL
	if base == "" {
		base = DefaultAPI
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("cveId", cve)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return &Record{CVE: strings.ToUpper(cve), Fetched: time.Now().UTC()}, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("nvd: rate limited (%s); an API key raises the limit", resp.Status)
	default:
		return nil, fmt.Errorf("nvd: %s", resp.Status)
	}
	rec, err := Parse(resp.Body)
	if errors.Is(err, ErrNotFound) {
		// Not in NVD yet: remember that, so it is asked again later.
		rec, err = &Record{CVE: strings.ToUpper(cve)}, nil
	}
	if err != nil {
		return nil, err
	}
	rec.Fetched = time.Now().UTC()
	return rec, nil
}

// Cache keeps fetched records on disk, one file per CVE.
type Cache struct {
	Dir string
}

var cveRE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func (c Cache) path(cve string) (string, bool) {
	cve = strings.ToUpper(cve)
	if !cveRE.MatchString(cve) {
		return "", false
	}
	return filepath.Join(c.Dir, cve+".json"), true
}

// Get returns a cached record.
func (c Cache) Get(cve string) (*Record, bool) {
	p, ok := c.path(cve)
	if !ok {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var rec Record
	if json.Unmarshal(data, &rec) != nil || rec.CVE == "" {
		return nil, false
	}
	return &rec, true
}

// Put stores a record atomically.
func (c Cache) Put(rec *Record) error {
	p, ok := c.path(rec.CVE)
	if !ok {
		return fmt.Errorf("nvd: invalid CVE id %q", rec.CVE)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".nvd-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Stale reports whether a cached record should be fetched again: records
// without analysis after a day, analysed ones after a week.
func Stale(rec *Record, now time.Time) bool {
	age := now.Sub(rec.Fetched)
	if len(rec.Matches) == 0 {
		return age > 24*time.Hour
	}
	return age > 7*24*time.Hour
}
