package match

import (
	"fmt"
	"strings"
	"time"

	"github.com/Legatia/hejnal/deps"
	"github.com/Legatia/hejnal/epss"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/osv"
)

// DepMatch is one advisory that covers one package where it was found.
type DepMatch struct {
	Package deps.Package
	Vuln    *osv.Vuln
}

// DependencyOptions say where the packages are and what is known about
// their flaws.
type DependencyOptions struct {
	// Project names the repository or image, as the Host of each finding.
	Project string
	Catalog *kev.Catalog
	EPSS    map[string]epss.Score
	Now     time.Time
}

// ratingScores rate advisories nobody is known to exploit, by their own
// severity: all low, so they wait in the quiet part of the list.
var ratingScores = map[string]int{"critical": 45, "high": 38, "medium": 28, "low": 15, "": 25}

// Dependencies turns advisories on packages into findings. What attackers
// do decides the order, not the advisory's own rating: malicious packages
// first, then flaws on a list of exploited ones, then flaws EPSS rates
// likely to be exploited soon; every other advisory is low, however its
// source rates it, because most are never exploited.
func Dependencies(ms []DepMatch, o DependencyOptions) []Finding {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	known := map[string]kev.Vulnerability{}
	if o.Catalog != nil {
		for _, v := range o.Catalog.Vulnerabilities {
			known[v.CVEID] = v
		}
	}
	var out []Finding
	for _, m := range ms {
		p, v := m.Package, m.Vuln
		f := Finding{
			Kind:       KindDependency,
			Host:       cleanText(o.Project),
			TechID:     cleanText(p.Ecosystem + ":" + p.Name),
			Technology: cleanText(p.Name),
			Version:    cleanText(p.Version),
			Ecosystem:  cleanText(p.Ecosystem),
			Advisory:   v.ID,
			Name:       cleanText(clip(firstNonEmpty(v.Summary, firstLine(v.Details)), 200)),
			File:       cleanText(p.File),
			Line:       p.Line,
			Dev:        p.Dev,
			Malicious:  v.Malicious(),
			FixedIn:    cleanText(v.FixedIn(p.Ecosystem, p.Name, p.Version)),
			Links:      []string{"https://osv.dev/vulnerability/" + v.ID},
			Confidence: ConfidenceVersion,
		}
		if p.Binary != "" && p.Binary != p.Name {
			f.Product = cleanText(p.Binary)
		}
		f.Aliases = v.CVEs()
		f.Rating = v.Rating(p.Ecosystem, p.Name)
		if len(f.Aliases) > 0 {
			f.CVE = f.Aliases[0]
		}
		scoreDependency(&f, known, o.EPSS, o.Now)
		f.Key = fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", KindDependency, f.Host, f.Ecosystem, f.Technology, f.Version, v.ID, f.File)
		out = append(out, f)
	}
	Sort(out)
	return out
}

// scoreDependency rates a dependency finding from what is known about its
// advisory's flaws now.
func scoreDependency(f *Finding, known map[string]kev.Vulnerability, scores map[string]epss.Score, now time.Time) {
	var exploited *kev.Vulnerability
	for _, c := range f.Aliases {
		if k, ok := known[c]; ok {
			exploited, f.CVE = &k, c
			break
		}
	}
	f.EPSS, f.EPSSPercentile = 0, 0
	for _, c := range f.Aliases {
		if e, ok := scores[c]; ok && probability(e.EPSS) > f.EPSS {
			f.EPSS, f.EPSSPercentile = probability(e.EPSS), probability(e.Percentile)
		}
	}
	f.DateAdded, f.DueDate, f.ListedBy, f.Ransomware = "", "", nil, false
	switch {
	case f.Malicious:
		// Installing it ran it: on developers' machines and in CI too.
		f.Score = 95
	case exploited != nil:
		f.DateAdded, f.DueDate, f.ListedBy = exploited.DateAdded, exploited.DueDate, listedBy(*exploited)
		f.Ransomware = exploited.Ransomware()
		f.Score = max(75, Score(*exploited, "library", f.EPSS, now)-5)
	case f.EPSS >= 0.5:
		f.Score = 75
	case f.EPSS >= 0.1:
		f.Score = 70
	case f.EPSS >= 0.01:
		f.Score = 50
	default:
		f.Score = ratingScores[f.Rating]
	}
	if f.Dev && !f.Malicious {
		// Code that only builds or tests the project does not run where
		// attackers reach it.
		f.Score = max(10, f.Score-20)
	}
	f.Severity = SeverityFor(f.Score)
}

// RescoreDependencies scores dependency findings again, for a later run:
// a flaw may have joined a list of exploited ones since the scan.
func RescoreDependencies(fs []Finding, cat *kev.Catalog, scores map[string]epss.Score, now time.Time) {
	known := map[string]kev.Vulnerability{}
	if cat != nil {
		for _, v := range cat.Vulnerabilities {
			known[v.CVEID] = v
		}
	}
	for i := range fs {
		if fs[i].Kind == KindDependency {
			scoreDependency(&fs[i], known, scores, now)
		}
	}
	Sort(fs)
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return strings.TrimSpace(x)
		}
	}
	return ""
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
