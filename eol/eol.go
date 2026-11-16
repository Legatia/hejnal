// Package eol reads endoflife.date: when each release of a product stops
// getting fixes. Hejnal uses it to flag software that runs a release past
// its end of support, and a release whose support ends soon, so the upgrade
// is planned work rather than a surprise.
package eol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is endoflife.date's API, with every product and release in one
// document.
const DefaultURL = "https://endoflife.date/api/v1/products/full"

// maxFeedBytes guards against a broken or hostile response filling memory.
// The whole document is about 3 MB.
const maxFeedBytes = 64 << 20

// Catalog is endoflife.date's list of products.
type Catalog struct {
	// Generated is the day endoflife.date generated the data, as
	// YYYY-MM-DD, if it says.
	Generated string
	products  map[string]*Product
}

// Product is one product and its releases, newest first.
type Product struct {
	// Name is the product's ID on endoflife.date, such as "nginx".
	Name     string
	Releases []Release
}

// Release is one release line of a product, such as nginx 1.24.
type Release struct {
	// Name is the release line, such as "1.24".
	Name string
	// EOL is the day support ends, as YYYY-MM-DD, or "" when no date is
	// known.
	EOL string
	// Ended is set when endoflife.date marks the release as past its end
	// of support, which it may do without a date.
	Ended bool
	// Latest is the newest version of the release, such as "1.24.0".
	Latest string
}

// Names and versions end up in reports as they are, so they must look like
// names and versions: a tampered feed cannot inject Markdown or links.
var (
	productRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	nameRE    = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,31}$`)
	dateRE    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

type document struct {
	GeneratedAt string `json:"generated_at"`
	Result      []struct {
		Name     string `json:"name"`
		Releases []struct {
			Name    string  `json:"name"`
			IsEOL   bool    `json:"isEol"`
			EOLFrom *string `json:"eolFrom"`
			Latest  *struct {
				Name string `json:"name"`
			} `json:"latest"`
		} `json:"releases"`
	} `json:"result"`
}

// Parse reads endoflife.date's document of all products. Products and
// releases whose names do not look like names are dropped, and dates and
// versions that do not look right are cleared.
func Parse(r io.Reader) (*Catalog, error) {
	var doc document
	if err := json.NewDecoder(io.LimitReader(r, maxFeedBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("eol: decode: %w", err)
	}
	c := &Catalog{products: map[string]*Product{}}
	if d, _, _ := strings.Cut(doc.GeneratedAt, "T"); validDate(d) {
		c.Generated = d
	}
	for _, p := range doc.Result {
		if !productRE.MatchString(p.Name) {
			continue
		}
		prod := &Product{Name: p.Name}
		for _, r := range p.Releases {
			if !nameRE.MatchString(r.Name) {
				continue
			}
			rel := Release{Name: r.Name, Ended: r.IsEOL}
			if r.EOLFrom != nil && validDate(*r.EOLFrom) {
				rel.EOL = *r.EOLFrom
			}
			if r.Latest != nil && nameRE.MatchString(r.Latest.Name) {
				rel.Latest = r.Latest.Name
			}
			prod.Releases = append(prod.Releases, rel)
		}
		if len(prod.Releases) > 0 {
			c.products[p.Name] = prod
		}
	}
	if len(c.products) == 0 {
		return nil, errors.New("eol: the document lists no products")
	}
	return c, nil
}

func validDate(s string) bool {
	if !dateRE.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.DateOnly, s)
	return err == nil
}

// Load reads a catalog from a local file.
func Load(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Fetch downloads the catalog and, when dest is set, stores the raw document
// there atomically, so a failed download never leaves a broken cache behind.
func Fetch(ctx context.Context, client *http.Client, url, userAgent, dest string) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("eol: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eol: download: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("eol: download: %w", err)
	}
	c, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	if dest != "" {
		if err := writeAtomic(dest, data); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Product returns the product with endoflife.date ID name.
func (c *Catalog) Product(name string) (*Product, bool) {
	if c == nil {
		return nil, false
	}
	p, ok := c.products[name]
	return p, ok
}

// Products returns how many products the catalog lists.
func (c *Catalog) Products() int {
	if c == nil {
		return 0
	}
	return len(c.products)
}

// Link is the product's page on endoflife.date.
func (p *Product) Link() string { return "https://endoflife.date/" + p.Name }

// Release returns the release line version belongs to: the release whose
// name is the longest prefix of version that ends where a number in it ends.
// Version 1.24.0 belongs to release 1.24, and 22.7R2 to 22.7, but 1.240 does
// not belong to 1.24.
func (p *Product) Release(version string) (Release, bool) {
	var best Release
	found := false
	for _, r := range p.Releases {
		if !strings.HasPrefix(version, r.Name) || found && len(r.Name) <= len(best.Name) {
			continue
		}
		if rest := version[len(r.Name):]; rest != "" && isDigit(rest[0]) {
			continue
		}
		if !isDigit(version[len(r.Name)-1]) {
			// A release name ends with its number; "1." is no release.
			continue
		}
		best, found = r, true
	}
	return best, found
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// Ends returns the day support ends, if a date is known.
func (r Release) Ends() (time.Time, bool) {
	if r.EOL == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateOnly, r.EOL)
	return t, err == nil
}

// EndedAt reports whether support has ended at now: from its end date on,
// or, without a date, when endoflife.date marks it as ended.
func (r Release) EndedAt(now time.Time) bool {
	if end, ok := r.Ends(); ok {
		return !now.Before(end)
	}
	return r.Ended
}

// supportedFor reports whether support lasts at least d from now. A release
// still supported with no end date announced lasts.
func (r Release) supportedFor(now time.Time, d time.Duration) bool {
	if end, ok := r.Ends(); ok {
		return end.Sub(now) >= d
	}
	return !r.Ended
}

// Upgrades returns versions to move release r to: the latest version of the
// closest newer release, and of the newest one, that stay supported for at
// least keep from now. It returns one version when they are the same
// release, and none when no newer release qualifies.
func (p *Product) Upgrades(r Release, now time.Time, keep time.Duration) []string {
	var closest, newest *Release
	for i := range p.Releases {
		c := &p.Releases[i]
		if c.Latest == "" || !c.supportedFor(now, keep) {
			continue
		}
		if cmp, ok := compareNames(c.Name, r.Name); !ok || cmp <= 0 {
			continue
		}
		if closest == nil || mustCompare(c.Name, closest.Name) < 0 {
			closest = c
		}
		if newest == nil || mustCompare(c.Name, newest.Name) > 0 {
			newest = c
		}
	}
	switch {
	case closest == nil:
		return nil
	case closest == newest:
		return []string{closest.Latest}
	}
	return []string{closest.Latest, newest.Latest}
}

// compareNames compares two release names made of numbers and dots, such as
// 1.24 and 1.3. ok is false when either is not of that form.
func compareNames(a, b string) (int, bool) {
	x, okA := numbers(a)
	y, okB := numbers(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case len(x) < len(y):
		return -1, true
	case len(x) > len(y):
		return 1, true
	}
	return 0, true
}

func mustCompare(a, b string) int {
	c, _ := compareNames(a, b)
	return c
}

func numbers(s string) ([]int, bool) {
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || p[0] == '+' {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func writeAtomic(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".eol-*.json")
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
	return os.Rename(tmp.Name(), dest)
}
