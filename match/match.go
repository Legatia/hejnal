// Package match turns an inventory into findings: products with flaws that
// attackers are exploiting now, and hygiene problems visible from outside.
package match

import (
	"cmp"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/epss"
	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/nvd"
)

// Kind is the type of a finding.
type Kind string

// Finding kinds.
const (
	KindKEV          Kind = "kev"           // product with a known exploited flaw
	KindTLSExpired   Kind = "tls-expired"   // certificate has expired
	KindTLSExpiring  Kind = "tls-expiring"  // certificate expires soon
	KindAdminExposed Kind = "admin-exposed" // admin interface reachable
	KindExposedFile  Kind = "exposed-file"  // a file, listing or test site that should not be public
	KindTakeover     Kind = "takeover"      // a name pointing at a hosting service where nothing is set up
	KindEmail        Kind = "email"         // mail records that let others send email as the domain
	KindSecret       Kind = "secret"        // a secret in source code, found by `hejnal leaks scan`
	KindBreach       Kind = "breach"        // accounts on a domain in a known data breach
)

// exposureScores rates exposed files: environment files usually hold
// passwords and keys, a .git directory gives away source code and often
// credentials, and a server status page shows live requests.
// A secret in a script is out already, a public bucket listing usually
// gives away private files, and a staging site often runs with test
// accounts and debug output.
var exposureScores = map[string]int{"env": 90, "git": 75, "server-status": 50,
	"script-secret": 95, "bucket-listing": 75, "directory-listing": 45, "non-production": 50, "foreign-host": 55}

// emailScores rates mail records by how easily they let others send email
// as the domain. A missing SPF record matters little where an enforced
// DMARC policy already turns fake email away.
var emailScores = map[string]int{"spf-missing": 55, "spf-missing-dmarc": 30, "spf-weak": 55, "dmarc-missing": 50, "dmarc-none": 40}

// Confidence says how sure Hejnal is.
const (
	// ConfidenceProduct means the product was recognised but its version
	// was not checked against the fix, so it may already be patched.
	ConfidenceProduct = "product"
	// ConfidenceVersion means the version seen is in NVD's affected range.
	ConfidenceVersion = "version"
	// ConfidenceRuledOut means the version seen is outside NVD's affected
	// ranges, so the flaw is probably fixed already.
	ConfidenceRuledOut = "ruled-out"
	// ConfidenceObserved means Hejnal saw the problem directly.
	ConfidenceObserved = "observed"
)

// Lists of exploited flaws, for Finding.ListedBy.
const (
	ListCISA  = "CISA"
	ListENISA = "ENISA"
)

// ENISAOnly reports whether only ENISA lists the flaw as exploited.
func (f Finding) ENISAOnly() bool {
	return len(f.ListedBy) == 1 && f.ListedBy[0] == ListENISA
}

// FirstListed returns the earliest date a list of exploited flaws included
// the flaw.
func (f Finding) FirstListed() string {
	if f.ENISAEarlier != "" && f.ENISAEarlier < f.DateAdded {
		return f.ENISAEarlier
	}
	return f.DateAdded
}

// RuledOut reports whether the version seen is outside the affected ranges.
func (f Finding) RuledOut() bool { return f.Confidence == ConfidenceRuledOut }

// Active returns the findings that are not ruled out.
func Active(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if !f.RuledOut() {
			out = append(out, f)
		}
	}
	return out
}

// Severity buckets a score into how soon to act.
type Severity string

// Severities, most urgent first.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

// Severities lists the buckets from most to least urgent.
var Severities = []Severity{Critical, High, Medium, Low}

// SeverityFor maps a 0–100 score to a severity.
func SeverityFor(score int) Severity {
	switch {
	case score >= 85:
		return Critical
	case score >= 70:
		return High
	case score >= 50:
		return Medium
	}
	return Low
}

// Rank orders severities; higher is more urgent. Unknown values rank 0.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// ParseSeverity reads a severity name. "none" returns "" with no error.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	if s == "none" || s == "" {
		return "", nil
	}
	if s.Rank() == 0 {
		return "", fmt.Errorf("unknown severity %q: use critical, high, medium, low or none", v)
	}
	return s, nil
}

// Finding is one thing worth acting on.
type Finding struct {
	Key         string `json:"key"`
	Kind        Kind   `json:"kind"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	URL         string `json:"url,omitempty"`
	TechID      string `json:"techId,omitempty"`
	Technology  string `json:"technology,omitempty"`
	Version     string `json:"version,omitempty"`
	Category    string `json:"category,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	CVE         string `json:"cve,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Product     string `json:"product,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Action      string `json:"action,omitempty"`
	DateAdded   string `json:"dateAdded,omitempty"`
	DueDate     string `json:"dueDate,omitempty"`
	// EUVD is the flaw's ID in ENISA's European Vulnerability Database.
	EUVD string `json:"euvd,omitempty"`
	// ListedBy names the lists of exploited flaws that include it: CISA,
	// ENISA or both. DateAdded is CISA's date, or ENISA's for a flaw only
	// ENISA lists.
	ListedBy []string `json:"listedBy,omitempty"`
	// ENISAEarlier is the date ENISA listed the flaw, when that was before
	// CISA added it.
	ENISAEarlier   string   `json:"enisaEarlier,omitempty"`
	Ransomware     bool     `json:"ransomware,omitempty"`
	Forensics      bool     `json:"forensics,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
	EPSSPercentile float64  `json:"epssPercentile,omitempty"`
	Links          []string `json:"links,omitempty"`
	// Packaged marks a version from a Linux distribution package, which
	// may contain backported fixes.
	Packaged bool `json:"packaged,omitempty"`
	// Condition names the platform the flaw needs according to NVD, such
	// as "microsoft windows"; the version seen is affected only there.
	Condition string     `json:"condition,omitempty"`
	Subject   string     `json:"subject,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	// File, Line and Commit locate a secret in source code. Commit is set
	// when the secret was found in the Git history. Fingerprint identifies
	// the secret without revealing it.
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Commit      string `json:"commit,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// BreachDate, Accounts and Passwords describe a data breach: when it
	// happened, how many accounts on the domain it exposed and whether it
	// exposed passwords.
	BreachDate string   `json:"breachDate,omitempty"`
	Accounts   int      `json:"accounts,omitempty"`
	Passwords  bool     `json:"passwords,omitempty"`
	Score      int      `json:"score"`
	Severity   Severity `json:"severity"`
	Confidence string   `json:"confidence"`
	// Accepted is set while a person's acceptance, made with `hejnal
	// accept`, covers the finding. Alerts and the exit status leave it out.
	Accepted *Acceptance `json:"accepted,omitempty"`
	// AcceptanceExpired is set when the acceptance that covered the finding
	// has expired, so the finding is open again.
	AcceptanceExpired *Acceptance `json:"acceptanceExpired,omitempty"`
}

// Options tune matching.
type Options struct {
	Now time.Time
	// EPSS scores by CVE, if available.
	EPSS map[string]epss.Score
	// ExpiryWindow flags certificates that expire within it. Default 21 days.
	ExpiryWindow time.Duration
	// NVD holds affected-version data by CVE, used when a product's
	// version is known.
	NVD map[string]*nvd.Record
}

// Run produces findings for an inventory, sorted most urgent first. cat may be
// nil, in which case only hygiene findings are produced.
func Run(inv *inventory.Inventory, cat *kev.Catalog, eng *fingerprint.Engine, opts Options) []Finding {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.ExpiryWindow <= 0 {
		opts.ExpiryWindow = 21 * 24 * time.Hour
	}
	out := []Finding{}
	seen := map[string]bool{}
	emit := func(f Finding) {
		if seen[f.Key] {
			return
		}
		seen[f.Key] = true
		out = append(out, f)
	}

	kevIndex := map[string][]int{}
	kevFor := func(id string) []int {
		if cat == nil || eng == nil || !eng.HasKEV(id) {
			return nil
		}
		if idx, ok := kevIndex[id]; ok {
			return idx
		}
		var idx []int
		for i, v := range cat.Vulnerabilities {
			if eng.MatchesKEV(id, v.VendorProject, v.Product, v.VulnerabilityName+" "+v.ShortDescription) {
				idx = append(idx, i)
			}
		}
		kevIndex[id] = idx
		return idx
	}

	for _, a := range inv.Assets {
		for _, s := range a.Services {
			if f, ok := tlsFinding(a.Host, s, opts); ok {
				emit(f)
			}
			for _, x := range s.Exposures {
				if x.Kind == "takeover" {
					// Anyone could serve pages, and read cookies set for
					// the parent domain, under this name.
					emit(Finding{
						Key: fmt.Sprintf("%s|%s|%d", KindTakeover, a.Host, s.Port), Kind: KindTakeover,
						Host: a.Host, Port: s.Port, URL: s.URL, Evidence: x.Evidence,
						Score: 80, Severity: SeverityFor(80), Confidence: ConfidenceObserved,
					})
					continue
				}
				score, ok := exposureScores[x.Kind]
				if !ok {
					score = 50
				}
				emit(Finding{
					Key:        fmt.Sprintf("%s|%s|%d|%s", KindExposedFile, a.Host, s.Port, x.Kind),
					Kind:       KindExposedFile,
					Host:       a.Host,
					Port:       s.Port,
					URL:        strings.TrimSuffix(s.URL, "/") + x.Path,
					TechID:     x.Kind,
					Evidence:   x.Evidence,
					Score:      score,
					Severity:   SeverityFor(score),
					Confidence: ConfidenceObserved,
				})
			}
			host, port, where := origin(a.Host, s)
			for _, t := range s.Technologies {
				base := Finding{
					Host:       host,
					Port:       port,
					URL:        where,
					TechID:     t.ID,
					Technology: t.Name,
					Version:    t.Version,
					Category:   t.Category,
					Evidence:   t.Evidence,
				}
				if t.Admin {
					f := base
					f.Kind = KindAdminExposed
					f.Key = fmt.Sprintf("%s|%s|%d|%s", f.Kind, host, port, t.ID)
					f.Score = 55
					f.Severity = SeverityFor(f.Score)
					f.Confidence = ConfidenceObserved
					emit(f)
				}
				for _, i := range kevFor(t.ID) {
					if t.Static {
						// The pages are static files: the application
						// the flaw is in does not run here.
						break
					}
					v := cat.Vulnerabilities[i]
					f := base
					f.Kind = KindKEV
					// One finding per flaw and service, even if two rules
					// recognise the same product.
					f.Key = fmt.Sprintf("%s|%s|%d|%s", f.Kind, host, port, v.CVEID)
					f.CVE = v.CVEID
					f.Vendor = v.VendorProject
					f.Product = v.Product
					f.Name = v.VulnerabilityName
					f.Description = v.ShortDescription
					f.Action = v.RequiredAction
					f.DateAdded = v.DateAdded
					f.DueDate = v.DueDate
					f.EUVD = v.EUVDID
					f.ListedBy = listedBy(v)
					f.ENISAEarlier = v.ENISAEarlier
					f.Ransomware = v.Ransomware()
					f.Forensics = v.Forensics()
					f.Links = v.Links()
					f.Confidence = ConfidenceProduct
					if e, ok := opts.EPSS[v.CVEID]; ok {
						f.EPSS, f.EPSSPercentile = probability(e.EPSS), probability(e.Percentile)
					}
					f.Score = Score(v, t.Category, f.EPSS, opts.Now)
					f.Packaged = t.Packaged
					applyVersion(&f, opts.NVD[v.CVEID], eng.CPEs(t.ID), eng.Edition(t.ID, t.Version))
					f.Severity = SeverityFor(f.Score)
					emit(f)
				}
			}
		}
	}
	for _, m := range inv.Mail {
		for _, p := range m.Problems() {
			ev := "SPF: " + orNone(m.SPF) + " · DMARC: " + orNone(m.DMARC)
			if m.DMARCDomain != "" {
				ev = "SPF: " + orNone(m.SPF) + " · DMARC: none of its own; " + m.DMARCDomain + "'s applies: " + m.DMARC
			}
			if len(m.MX) == 0 {
				ev += " · the domain receives no email"
			}
			emit(Finding{
				Key: fmt.Sprintf("%s|%s|%s", KindEmail, m.Domain, p), Kind: KindEmail,
				Host: m.Domain, TechID: p, Evidence: ev,
				Score: emailScores[p], Severity: SeverityFor(emailScores[p]), Confidence: ConfidenceObserved,
			})
		}
	}
	Sort(out)
	return out
}

func orNone(record string) string {
	if record == "" {
		return "none"
	}
	return record
}

func listedBy(v kev.Vulnerability) []string {
	switch {
	case v.ENISAOnly:
		return []string{ListENISA}
	case v.ENISA:
		return []string{ListCISA, ListENISA}
	}
	return []string{ListCISA}
}

// Score rates a known exploited flaw on a product from 0 to 100. Recently
// added flaws matter most, because that is when attackers scan for them at
// scale; edge devices, ransomware use, CISA's call for forensic triage and
// the EPSS probability raise the score.
func Score(v kev.Vulnerability, category string, epssScore float64, now time.Time) int {
	score := 60
	if added, ok := v.Added(); ok {
		age := now.Sub(added)
		switch {
		case age <= 30*24*time.Hour:
			score += 20
		case age <= 90*24*time.Hour:
			score += 10
		case age > 365*24*time.Hour:
			score -= 20
		}
	}
	switch category {
	case "edge", "remote-access", "network", "camera":
		// Internet-facing gateways, remote access tools and devices are
		// what attackers scan for first.
		score += 10
	}
	if v.Ransomware() {
		score += 10
	}
	if v.Forensics() {
		score += 5
	}
	score += int(math.Round(probability(epssScore) * 10))
	return max(0, min(100, score))
}

// ruledOutScore caps the score of flaws the version check rules out.
const ruledOutScore = 20

// applyVersion compares the version seen with NVD's affected ranges.
// edition is the product's NVD software edition, when the rule can tell.
func applyVersion(f *Finding, rec *nvd.Record, products []string, edition string) {
	if rec == nil || f.Version == "" || len(products) == 0 {
		return
	}
	verdict, platforms := rec.Check(products, f.Version, edition)
	switch verdict {
	case nvd.Affected:
		// Distribution packages often carry backported fixes under an old
		// version number, so only upstream builds count as confirmed.
		if !f.Packaged {
			f.Confidence = ConfidenceVersion
			f.Score = min(100, f.Score+10)
		}
	case nvd.AffectedOnPlatform:
		names := make([]string, len(platforms))
		for i, p := range platforms {
			names[i] = strings.NewReplacer(":", " ", "_", " ").Replace(p)
		}
		f.Condition = strings.Join(names, " or ")
	case nvd.NotAffected:
		f.Confidence = ConfidenceRuledOut
		f.Score = min(f.Score, ruledOutScore)
	}
}

// probability keeps a value within 0–1, treating anything invalid as 0.
func probability(p float64) float64 {
	if !(p >= 0) { // also catches NaN
		return 0
	}
	return min(p, 1)
}

func tlsFinding(host string, s inventory.Service, opts Options) (Finding, bool) {
	if s.TLS == nil || s.TLS.NotAfter.IsZero() {
		return Finding{}, false
	}
	expires := s.TLS.NotAfter
	f := Finding{
		Host:       host,
		Port:       s.Port,
		URL:        s.URL,
		Subject:    s.TLS.Subject,
		Expires:    &expires,
		Confidence: ConfidenceObserved,
	}
	switch left := expires.Sub(opts.Now); {
	case left < 0:
		f.Kind, f.Score = KindTLSExpired, 70
	case left < opts.ExpiryWindow:
		f.Kind, f.Score = KindTLSExpiring, 50
	default:
		return Finding{}, false
	}
	f.Key = fmt.Sprintf("%s|%s|%d", f.Kind, host, s.Port)
	f.Severity = SeverityFor(f.Score)
	return f, true
}

// origin returns where a service's software actually answered: the host and
// port of the final URL after redirects, so http→https redirects do not
// produce the same finding twice.
func origin(host string, s inventory.Service) (string, int, string) {
	raw := s.FinalURL
	if raw == "" {
		raw = s.URL
	}
	if raw == "" {
		// A service known only by its banner, such as a mail server.
		h := host
		if ip := net.ParseIP(h); ip != nil {
			h = ip.String()
		}
		return h, s.Port, "tcp://" + net.JoinHostPort(h, strconv.Itoa(s.Port))
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return host, s.Port, raw
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	} else if u.Scheme == "https" {
		port = 443
	} else if u.Scheme == "http" {
		port = 80
	}
	if port == 0 {
		port = s.Port
	}
	h := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(h); ip != nil {
		h = ip.String()
	}
	return h, port, raw
}

// Sort orders findings most urgent first, then newest flaw first.
func Sort(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		if c := strings.Compare(b.DateAdded, a.DateAdded); c != 0 {
			return c
		}
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Port, b.Port); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
}

// Group is one item to fix: all known exploited flaws of one product on one
// service, every place one secret was found, all breaches of one domain, or a
// single hygiene finding.
type Group struct {
	// Key identifies the item across runs: kind, host, port and product for
	// known exploited flaws, the fingerprint for a secret, the domain for
	// breaches, and the finding's key otherwise.
	Key        string
	Kind       Kind
	Host       string
	Port       int
	URL        string
	TechID     string
	Technology string
	Version    string
	Category   string
	Evidence   string
	Score      int
	Severity   Severity
	Findings   []Finding
}

// Forensics reports whether CISA asks for forensic triage of any flaw in the
// group.
func (g Group) Forensics() bool {
	return slices.ContainsFunc(g.Findings, func(f Finding) bool { return f.Forensics })
}

// Newest returns the most recent date a flaw in the group was added to a list
// of exploited flaws.
func (g Group) Newest() string {
	newest := ""
	for _, f := range g.Findings {
		newest = max(newest, f.DateAdded)
	}
	return newest
}

// GroupKey returns the key of the item a finding belongs to: all known
// exploited flaws of one product on one service, every place one secret was
// found, all breaches of one domain, or the finding itself.
func GroupKey(f Finding) string {
	switch f.Kind {
	case KindKEV:
		return fmt.Sprintf("%s|%s|%d|%s", f.Kind, f.Host, f.Port, f.TechID)
	case KindSecret:
		// One secret to replace, wherever it was found.
		return fmt.Sprintf("%s|%s", f.Kind, f.Fingerprint)
	case KindBreach:
		return fmt.Sprintf("%s|%s", f.Kind, f.Host)
	}
	return f.Key
}

// Groups collects findings into items to fix, most urgent first.
func Groups(fs []Finding) []Group {
	sorted := slices.Clone(fs)
	Sort(sorted)
	idx := map[string]int{}
	var out []Group
	for _, f := range sorted {
		k := GroupKey(f)
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, Group{
				Key:        k,
				Kind:       f.Kind,
				Host:       f.Host,
				Port:       f.Port,
				URL:        f.URL,
				TechID:     f.TechID,
				Technology: f.Technology,
				Version:    f.Version,
				Category:   f.Category,
				Evidence:   f.Evidence,
				Score:      f.Score,
				Severity:   f.Severity,
			})
		}
		out[i].Findings = append(out[i].Findings, f)
	}
	slices.SortStableFunc(out, func(a, b Group) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return cmp.Compare(a.Port, b.Port)
	})
	return out
}

// CountGroups returns how many groups fall in each severity.
func CountGroups(gs []Group) map[Severity]int {
	c := map[Severity]int{}
	for _, g := range gs {
		c[g.Severity]++
	}
	return c
}

// AtLeast reports whether any finding is at or above the given severity.
func AtLeast(fs []Finding, s Severity) bool {
	if s == "" {
		return false
	}
	return slices.ContainsFunc(fs, func(f Finding) bool { return f.Severity.Rank() >= s.Rank() })
}

// CVEs lists the distinct CVE IDs in the findings.
func CVEs(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if f.CVE != "" {
			out = append(out, f.CVE)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
