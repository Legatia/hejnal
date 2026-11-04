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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	Update string `json:"update,omitempty"`
	// Edition limits the entry to one software edition of the product,
	// such as "lts" for Jenkins' long-term support line or "-" for its
	// weekly line.
	Edition        string `json:"edition,omitempty"`
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
				if n.Negate {
					// "Not on this platform" is not a platform the flaw needs.
					continue
				}
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
				if c.edition != "*" && c.edition != "" {
					mt.Edition = c.edition
				}
				rec.Matches = append(rec.Matches, mt)
			}
		}
	}
	return rec, nil
}

type cpe struct{ vendor, product, version, update, edition string }

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
	c := cpe{
		vendor:  strings.ToLower(fields[3]),
		product: strings.ToLower(fields[4]),
		version: strings.ToLower(fields[5]),
		update:  strings.ToLower(fields[6]),
	}
	// The tenth component is the software edition.
	if len(fields) > 9 {
		c.edition = strings.ToLower(fields[9])
	}
	return c, true
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
// names) is affected. edition is the product's software edition when it is
// known, such as "lts", and empty otherwise. For AffectedOnPlatform it also
// returns the platforms.
//
// Check answers NotAffected only when every entry for the product could be
// evaluated and none covers the version. A shortened version ("2.4" from a
// server that hides its patch level), an entry it cannot parse, a
// pre-release entry with the same number, or an edition it cannot tell
// apart all make the answer Unknown instead, so guesswork never rules out a
// vulnerable system.
func (r *Record) Check(products []string, version, edition string) (Verdict, []string) {
	if r == nil || version == "" {
		return Unknown, nil
	}
	v, ok := ParseVersion(version)
	if !ok {
		return Unknown, nil
	}
	applicable, affected, uncertain := false, false, false
	var platforms []string
	// Entries limited to an edition, when the edition seen is unknown: the
	// editions listed and those whose entries cover the version.
	editions, editionsHit := map[string]bool{}, map[string]bool{}
	for _, m := range r.Matches {
		if !slices.Contains(products, m.Vendor+":"+m.Product) {
			continue
		}
		if m.Edition != "" && edition != "" && m.Edition != edition {
			continue // another edition's entry
		}
		applicable = true
		res := m.covers(v)
		switch {
		case res == maybe:
			uncertain = true
			continue
		case m.Edition != "" && edition == "":
			editions[m.Edition] = true
			if res == yes {
				if len(m.Platforms) > 0 {
					uncertain = true
				} else {
					editionsHit[m.Edition] = true
				}
			}
			continue
		case res == no:
			continue
		}
		if len(m.Platforms) > 0 {
			platforms = append(platforms, m.Platforms...)
		} else {
			affected = true
		}
	}
	if len(editionsHit) > 0 {
		if len(editionsHit) == len(editions) {
			affected = true // affected whichever edition it is
		} else {
			uncertain = true
		}
	}
	switch {
	case affected:
		return Affected, nil
	case uncertain:
		return Unknown, nil
	case len(platforms) > 0:
		slices.Sort(platforms)
		return AffectedOnPlatform, slices.Compact(platforms)
	case applicable:
		return NotAffected, nil
	}
	return Unknown, nil
}

// tri is a three-valued answer.
type tri int

const (
	no tri = iota
	yes
	maybe
)

// covers reports whether the entry covers version v.
func (m Match) covers(v Version) tri {
	if m.Version != "" {
		exact, ok := ParseVersion(m.Version)
		if !ok {
			return maybe
		}
		if m.Update != "" {
			// A qualified build, such as 10.1.0 milestone 17. Hejnal cannot
			// tell it from the version it saw when the numbers are the same.
			if v.compareNumbers(exact).has(0) {
				return maybe
			}
			return no
		}
		switch o := v.compare(exact); {
		case o == equal:
			return yes
		case !o.has(0):
			return no
		}
		return maybe
	}
	result := yes
	for _, c := range []struct {
		bound  string
		accept func(int) bool
	}{
		{m.StartIncluding, func(c int) bool { return c >= 0 }},
		{m.StartExcluding, func(c int) bool { return c > 0 }},
		{m.EndIncluding, func(c int) bool { return c <= 0 }},
		{m.EndExcluding, func(c int) bool { return c < 0 }},
	} {
		if c.bound == "" {
			continue
		}
		b, ok := ParseVersion(c.bound)
		if !ok {
			return maybe
		}
		switch o := v.compare(b); {
		case !o.any(c.accept):
			return no
		case !o.all(c.accept):
			result = maybe
		}
	}
	return result
}

// outcome is the set of possible results of comparing two versions: a
// shortened version can be less than, equal to or greater than a bound.
type outcome uint8

const (
	less outcome = 1 << iota
	equal
	greater
)

func outcomeOf(c int) outcome {
	switch {
	case c < 0:
		return less
	case c > 0:
		return greater
	}
	return equal
}

func (o outcome) has(c int) bool { return o&outcomeOf(c) != 0 }

func (o outcome) all(accept func(int) bool) bool {
	for _, c := range []int{-1, 0, 1} {
		if o.has(c) && !accept(c) {
			return false
		}
	}
	return true
}

func (o outcome) any(accept func(int) bool) bool {
	for _, c := range []int{-1, 0, 1} {
		if o.has(c) && accept(c) {
			return true
		}
	}
	return false
}

// Version is a dotted numeric version with an optional pre-release suffix.
type Version struct {
	nums []int
	pre  string
}

var versionRE = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)(?:[-_.~+]?((?:alpha|beta|rc|preview|pre|dev|snapshot|milestone|m|a|b)[0-9.]*))?$`)

// ParseVersion reads versions such as "8.3.12", "6.8", "2.462.3" or
// "10.1.0-rc1".
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

// Compare returns -1, 0 or 1, counting missing components as zero, so
// "6.8" equals "6.8.0". A pre-release sorts before its release.
func (v Version) Compare(o Version) int {
	if c := compareNums(v.nums, o.nums); c != 0 {
		return c
	}
	return comparePre(v.pre, o.pre)
}

// compare is Compare for a version seen on a system. A version without a
// pre-release that has fewer components than the other, such as "2.4"
// against "2.4.49", stands for any version that starts that way, so the
// result may be any of several.
func (v Version) compare(b Version) outcome {
	n := min(len(v.nums), len(b.nums))
	if c := compareNums(v.nums[:n], b.nums[:n]); c != 0 {
		return outcomeOf(c)
	}
	if len(v.nums) < len(b.nums) && v.pre == "" {
		zeros := !slices.ContainsFunc(b.nums[n:], func(x int) bool { return x != 0 })
		if zeros && b.pre == "" {
			// "2.4" against "2.4.0": every 2.4.x is at least 2.4.0.
			return equal | greater
		}
		return less | equal | greater
	}
	return outcomeOf(v.Compare(b))
}

// compareNumbers is compare without the pre-release suffixes.
func (v Version) compareNumbers(b Version) outcome {
	v.pre, b.pre = "", ""
	return v.compare(b)
}

func compareNums(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// preStages orders pre-release labels: development builds first, then
// alpha, beta, milestone, preview and release candidate.
var preStages = map[string]int{
	"dev": 0, "snapshot": 0,
	"alpha": 1, "a": 1,
	"beta": 2, "b": 2,
	"milestone": 3, "m": 3,
	"pre": 4, "preview": 4,
	"rc": 5,
}

// comparePre compares pre-release suffixes by stage, then by number, so rc9
// comes before rc10. No suffix, a release, comes last.
func comparePre(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	sa, na := splitPre(a)
	sb, nb := splitPre(b)
	if sa != sb {
		if sa < sb {
			return -1
		}
		return 1
	}
	return compareNums(na, nb)
}

func splitPre(p string) (stage int, nums []int) {
	i := strings.IndexFunc(p, func(r rune) bool { return r < 'a' || r > 'z' })
	if i < 0 {
		i = len(p)
	}
	stage = preStages[p[:i]]
	for _, f := range strings.Split(p[i:], ".") {
		if f == "" {
			continue
		}
		n := 0
		for _, d := range f {
			if n < 1e8 {
				n = n*10 + int(d-'0')
			}
		}
		nums = append(nums, n)
	}
	return stage, nums
}

// Client fetches CVE records from the NVD API, pacing requests to stay
// within NVD's public rate limits. All clients in a process that use the
// same API address and key share one pace.
type Client struct {
	HTTP      *http.Client
	BaseURL   string
	APIKey    string
	UserAgent string
	// Pause overrides the pause between requests (for tests).
	Pause time.Duration
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

// pacer hands out request slots at least one interval apart.
type pacer struct {
	mu   sync.Mutex
	next time.Time
}

var pacers sync.Map // API address and key → *pacer

func (c *Client) pacer(base string) *pacer {
	key := base + "\x00"
	if c.APIKey != "" {
		sum := sha256.Sum256([]byte(c.APIKey))
		key += hex.EncodeToString(sum[:8])
	}
	p, _ := pacers.LoadOrStore(key, &pacer{})
	return p.(*pacer)
}

// wait reserves the next request slot and waits for it.
func (c *Client) wait(ctx context.Context, base string) error {
	p := c.pacer(base)
	p.mu.Lock()
	slot := time.Now()
	if p.next.After(slot) {
		slot = p.next
	}
	p.next = slot.Add(c.Interval())
	p.mu.Unlock()
	d := time.Until(slot)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Fetch downloads one CVE record.
func (c *Client) Fetch(ctx context.Context, cve string) (*Record, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if !cveRE.MatchString(cve) {
		return nil, fmt.Errorf("nvd: invalid CVE id %q", cve)
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultAPI
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("nvd: invalid API address %q", base)
	}
	if c.APIKey != "" && u.Scheme != "https" && !loopback(u.Hostname()) {
		return nil, errors.New("nvd: the API key is only sent over https")
	}
	if err := c.wait(ctx, base); err != nil {
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
	client := http.Client{Timeout: time.Minute}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	// NVD's API does not redirect, and following a redirect would carry the
	// API key to wherever it points.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return &Record{CVE: cve, Fetched: time.Now().UTC()}, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("nvd: rate limited (%s); an API key raises the limit", resp.Status)
	default:
		return nil, fmt.Errorf("nvd: %s", resp.Status)
	}
	rec, err := Parse(resp.Body)
	if errors.Is(err, ErrNotFound) {
		// Not in NVD yet: remember that, so it is asked again later.
		rec, err = &Record{CVE: cve}, nil
	}
	if err != nil {
		return nil, err
	}
	if rec.CVE != cve {
		return nil, fmt.Errorf("nvd: asked for %s but the answer is about %s", cve, rec.CVE)
	}
	rec.Fetched = time.Now().UTC()
	return rec, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	if json.Unmarshal(data, &rec) != nil || !strings.EqualFold(rec.CVE, cve) {
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
// without analysis after a day, analysed ones after a week, and any record
// dated in the future.
func Stale(rec *Record, now time.Time) bool {
	age := now.Sub(rec.Fetched)
	if age < -time.Hour {
		return true
	}
	if len(rec.Matches) == 0 {
		return age > 24*time.Hour
	}
	return age > 7*24*time.Hour
}
