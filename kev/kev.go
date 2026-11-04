// Package kev reads CISA's Known Exploited Vulnerabilities (KEV) catalog: the
// public list of flaws that attackers are known to exploit in the wild.
package kev

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
	"strings"
	"time"
)

// DefaultURL is CISA's published JSON feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// maxFeedBytes guards against a broken or hostile response filling memory.
const maxFeedBytes = 64 << 20

// Catalog is the KEV feed.
type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is one known-exploited flaw.
type Vulnerability struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	ForensicTriage             string   `json:"forensicTriage,omitempty"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

var (
	cveRE     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	dateRE    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	versionRE = regexp.MustCompile(`^[0-9A-Za-z._-]{1,32}$`)
)

// Parse decodes a catalog and normalises its text fields. CISA's data
// contains stray and non-breaking spaces in vendor and product names.
// Fields that end up in reports as they are must have the expected form:
// entries without a valid CVE ID are dropped, and malformed dates and
// catalog versions are cleared, so a tampered feed cannot inject Markdown.
func Parse(r io.Reader) (*Catalog, error) {
	var c Catalog
	if err := json.NewDecoder(io.LimitReader(r, maxFeedBytes)).Decode(&c); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	if !versionRE.MatchString(c.CatalogVersion) {
		c.CatalogVersion = ""
	}
	vulns := c.Vulnerabilities[:0]
	for _, v := range c.Vulnerabilities {
		v.CVEID = strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !cveRE.MatchString(v.CVEID) {
			continue
		}
		v.VendorProject = squash(v.VendorProject)
		v.Product = squash(v.Product)
		v.VulnerabilityName = squash(v.VulnerabilityName)
		v.DateAdded = date(v.DateAdded)
		v.DueDate = date(v.DueDate)
		vulns = append(vulns, v)
	}
	c.Vulnerabilities = vulns
	if len(c.Vulnerabilities) == 0 {
		return nil, errors.New("kev: catalog has no vulnerabilities")
	}
	return &c, nil
}

// date returns a YYYY-MM-DD date, or "" for anything else.
func date(s string) string {
	s = strings.TrimSpace(s)
	if !dateRE.MatchString(s) {
		return ""
	}
	return s
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

// Fetch downloads the catalog and, when dest is set, stores the raw feed there
// atomically so a failed download never leaves a broken cache behind.
func Fetch(ctx context.Context, client *http.Client, url, userAgent, dest string) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: download: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("kev: download: %w", err)
	}
	cat, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	if dest != "" {
		if err := writeAtomic(dest, data); err != nil {
			return nil, err
		}
	}
	return cat, nil
}

// Ransomware reports whether CISA links the flaw to ransomware campaigns.
func (v Vulnerability) Ransomware() bool {
	return strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known")
}

// Forensics reports whether CISA asks for forensic triage, meaning systems
// that were exposed should be checked for compromise, not only patched.
func (v Vulnerability) Forensics() bool {
	return strings.EqualFold(strings.TrimSpace(v.ForensicTriage), "Yes")
}

// Added returns the date CISA added the flaw to the catalog.
func (v Vulnerability) Added() (time.Time, bool) {
	t, err := time.Parse("2006-01-02", v.DateAdded)
	return t, err == nil
}

// Links returns the advisory URLs from the notes field, leaving out CISA's
// generic directive pages so vendor advisories come first. Only plain http
// and https URLs are returned, without characters that could break out of
// a Markdown link.
func (v Vulnerability) Links() []string {
	var vendor, cisa []string
	for _, part := range strings.FieldsFunc(v.Notes, func(r rune) bool { return r == ';' || r == ' ' }) {
		u := strings.TrimSpace(part)
		if !safeURL(u) {
			continue
		}
		if strings.Contains(u, "cisa.gov/news-events/directives") {
			cisa = append(cisa, u)
			continue
		}
		vendor = append(vendor, u)
	}
	return append(vendor, cisa...)
}

func safeURL(s string) bool {
	if len(s) > 512 || strings.ContainsAny(s, "<>\"'`\\{}|^ ") {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

func squash(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func writeAtomic(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".kev-*.json")
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
