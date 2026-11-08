// Package euvd reads the European Union's list of exploited vulnerabilities
// from ENISA's European Vulnerability Database (EUVD).
//
// ENISA publishes its own list of flaws exploited in the wild, partly from
// European CSIRTs, alongside CISA's. Hejnal uses it in three ways: to show
// each flaw's EUVD ID, to report flaws that only ENISA lists, and to show
// when ENISA listed a flaw before CISA did.
//
// Source: ENISA European Vulnerability Database (EUVD),
// https://euvd.enisa.europa.eu. ENISA's legal notice allows reuse of its
// material with acknowledgement of the source.
package euvd

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
	"time"
)

const (
	// DefaultURL is the daily dump of ENISA's exploited vulnerabilities list.
	DefaultURL = "https://euvdservices.enisa.europa.eu/api/kev/dump"
	// DefaultRecordURL returns one EUVD record by EUVD or CVE ID.
	DefaultRecordURL = "https://euvdservices.enisa.europa.eu/api/enisaid"
)

// Source names in the dump.
const (
	SourceCISA  = "cisa_kev"
	SourceENISA = "eukev_kev"
)

// maxBytes guards against a broken or hostile response filling memory. The
// dump is about 260 KB and a record a few KB.
const (
	maxDumpBytes   = 16 << 20
	maxRecordBytes = 1 << 20
)

// ErrNotFound means the EUVD has no record with that ID.
var ErrNotFound = errors.New("euvd: not found")

// Entry is one flaw on the list.
type Entry struct {
	CVEID  string `json:"cveId"`
	EUVDID string `json:"euvdId"`
	// VendorProject and Product are set only on entries from ENISA's own
	// list. They are free text, less consistent than CISA's.
	VendorProject     string `json:"vendorProject,omitempty"`
	Product           string `json:"product,omitempty"`
	VulnerabilityName string `json:"vulnerabilityName,omitempty"`
	// DateAdded is the earliest date any of the sources listed the flaw.
	DateAdded string   `json:"dateAdded"`
	Sources   []string `json:"sources"`
}

// ENISA reports whether ENISA's own list includes the flaw.
func (e Entry) ENISA() bool { return slices.Contains(e.Sources, SourceENISA) }

var (
	cveRE    = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	euvdRE   = regexp.MustCompile(`^EUVD-[0-9]{4}-[0-9]{1,9}$`)
	dateRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	maxField = 200
)

// Parse decodes the dump. Entries without a valid CVE ID, EUVD ID or date
// are dropped, and only known sources are kept, so a tampered feed cannot
// inject Markdown into reports through these fields.
func Parse(r io.Reader) ([]Entry, error) {
	var raw []Entry
	if err := json.NewDecoder(io.LimitReader(r, maxDumpBytes)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("euvd: decode: %w", err)
	}
	out := raw[:0]
	for _, e := range raw {
		e.CVEID = strings.ToUpper(strings.TrimSpace(e.CVEID))
		e.EUVDID = strings.ToUpper(strings.TrimSpace(e.EUVDID))
		e.DateAdded = strings.TrimSpace(e.DateAdded)
		if !cveRE.MatchString(e.CVEID) || !euvdRE.MatchString(e.EUVDID) || !dateRE.MatchString(e.DateAdded) {
			continue
		}
		e.VendorProject = clean(e.VendorProject, maxField)
		e.Product = clean(e.Product, maxField)
		e.VulnerabilityName = clean(e.VulnerabilityName, maxField)
		var src []string
		for _, s := range e.Sources {
			if s == SourceCISA || s == SourceENISA {
				src = append(src, s)
			}
		}
		e.Sources = src
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, errors.New("euvd: the list has no entries")
	}
	return out, nil
}

// Load reads a saved dump.
func Load(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Fetch downloads the dump and, when dest is set, saves it there atomically
// so a failed download never leaves a broken copy behind.
func Fetch(ctx context.Context, client *http.Client, rawURL, userAgent, dest string) ([]Entry, error) {
	data, err := get(ctx, client, rawURL, userAgent, maxDumpBytes)
	if err != nil {
		return nil, err
	}
	entries, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	if dest != "" {
		if err := writeAtomic(dest, data); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// Published returns when ENISA last regenerated the dump: every day at
// 07:00 UTC. A copy saved before then is out of date.
func Published(now time.Time) time.Time {
	now = now.UTC()
	t := time.Date(now.Year(), now.Month(), now.Day(), 7, 0, 0, 0, time.UTC)
	if now.Before(t) {
		t = t.AddDate(0, 0, -1)
	}
	return t
}

// Record is the part of an EUVD record Hejnal uses.
type Record struct {
	ID          string
	Description string
	// References are the advisory URLs, http and https only.
	References []string
	// Products lists the affected products and version ranges ENISA gives,
	// such as "7.9 <7.23.4".
	Products []Product
}

// Product is one affected product in a record.
type Product struct {
	Vendor   string `json:"vendor"`
	Name     string `json:"name"`
	Versions string `json:"versions,omitempty"`
}

// rawRecord is the API's format. Dates are locale strings without a time
// zone, and aliases and references are newline-separated strings; other
// fields that are not well-formed JSON objects are left out on purpose.
type rawRecord struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	References  string `json:"references"`
	Products    []struct {
		Product struct {
			Name   string `json:"name"`
			Vendor struct {
				Name string `json:"name"`
			} `json:"vendor"`
		} `json:"product"`
		Version string `json:"product_version"`
	} `json:"enisaIdProduct"`
}

// maxDescription limits how much of a description is kept.
const maxDescription = 2000

// ParseRecord decodes one record.
func ParseRecord(r io.Reader) (*Record, error) {
	var raw rawRecord
	if err := json.NewDecoder(io.LimitReader(r, maxRecordBytes)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("euvd: decode record: %w", err)
	}
	id := strings.ToUpper(strings.TrimSpace(raw.ID))
	if !euvdRE.MatchString(id) {
		return nil, fmt.Errorf("euvd: record has no valid EUVD ID")
	}
	rec := &Record{ID: id, Description: clean(raw.Description, maxDescription)}
	for _, line := range strings.Split(raw.References, "\n") {
		if u := strings.TrimSpace(line); SafeURL(u) && !slices.Contains(rec.References, u) && len(rec.References) < 20 {
			rec.References = append(rec.References, u)
		}
	}
	for _, p := range raw.Products {
		prod := Product{Vendor: clean(p.Product.Vendor.Name, maxField), Name: clean(p.Product.Name, maxField), Versions: clean(p.Version, maxField)}
		if prod.Name != "" && !slices.Contains(rec.Products, prod) && len(rec.Products) < 50 {
			rec.Products = append(rec.Products, prod)
		}
	}
	return rec, nil
}

// FetchRecord downloads one record by EUVD ID. It returns ErrNotFound when
// the EUVD has no such record.
func FetchRecord(ctx context.Context, client *http.Client, baseURL, userAgent, id string) (*Record, error) {
	if !euvdRE.MatchString(id) {
		return nil, fmt.Errorf("euvd: invalid EUVD ID %q", id)
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("id", id)
	u.RawQuery = q.Encode()
	data, err := get(ctx, client, u.String(), userAgent, maxRecordBytes)
	if err != nil {
		return nil, err
	}
	rec, err := ParseRecord(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	if rec.ID != id {
		return nil, fmt.Errorf("euvd: asked for %s, got %s", id, rec.ID)
	}
	return rec, nil
}

// Cache keeps records on disk, one file per EUVD ID.
type Cache struct{ Dir string }

type cached struct {
	Fetched time.Time `json:"fetched"`
	Record
}

// Get returns a cached record and when it was fetched.
func (c Cache) Get(id string) (*Record, time.Time, bool) {
	if !euvdRE.MatchString(id) {
		return nil, time.Time{}, false
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, id+".json"))
	if err != nil {
		return nil, time.Time{}, false
	}
	var v cached
	if err := json.Unmarshal(data, &v); err != nil || v.ID != id {
		return nil, time.Time{}, false
	}
	return &v.Record, v.Fetched, true
}

// Put saves a record.
func (c Cache) Put(rec *Record, fetched time.Time) error {
	if !euvdRE.MatchString(rec.ID) {
		return fmt.Errorf("euvd: invalid EUVD ID %q", rec.ID)
	}
	data, err := json.Marshal(cached{Fetched: fetched.UTC(), Record: *rec})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(c.Dir, rec.ID+".json"), data)
}

func get(ctx context.Context, client *http.Client, rawURL, userAgent string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("euvd: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("euvd: download: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("euvd: download: %w", err)
	}
	return data, nil
}

// SafeURL reports whether s is a plain http or https URL without characters
// that could break out of a Markdown link.
func SafeURL(s string) bool {
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

// clean collapses whitespace, including non-breaking spaces, drops control
// characters and limits the length.
func clean(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, " ", " ")), " ")
	if len(s) > limit {
		cut := limit
		for cut > 0 && (s[cut]&0xc0) == 0x80 {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

func writeAtomic(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".euvd-*.json")
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
