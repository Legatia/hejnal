package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/Legatia/hejnal/match"
)

// SARIF writes findings as a SARIF 2.1.0 log, the format GitHub code
// scanning and other tools import. Each item becomes one result at its
// first file, with the item's title, what to do, and GitHub's
// security-severity, so urgent items surface first there too.
func SARIF(w io.Writer, findings []match.Finding, toolVersion, lang string) error {
	tr := newTranslator(lang)
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription msg               `json:"shortDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]string `json:"properties"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine"`
			} `json:"region,omitempty"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
	}
	var rules []rule
	seen := map[string]bool{}
	results := []result{}
	for _, g := range match.Groups(match.Open(findings)) {
		f := g.Findings[0]
		if f.File == "" {
			continue // SARIF results point at files; others belong in the fix list
		}
		id, name, help := sarifRule(g)
		if !seen[id] {
			seen[id] = true
			rules = append(rules, rule{ID: id, Name: name, ShortDescription: msg{plain(itemTitle(tr, g))}, HelpURI: help,
				Properties: map[string]string{"security-severity": securitySeverity(g.Severity), "tags": "security"}})
		}
		why, todo := itemText(tr, g)
		text := plain(groupTitle(tr, g))
		if todo != "" {
			text += ". " + plain(todo)
		}
		if why != "" {
			text += " " + plain(why)
		}
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = sarifURI(f.File)
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &struct {
				StartLine int `json:"startLine"`
			}{f.Line}
		}
		sum := sha256.Sum256([]byte(g.Key))
		results = append(results, result{RuleID: id, Level: sarifLevel(g.Severity), Message: msg{text}, Locations: []location{loc},
			PartialFingerprints: map[string]string{"hejnalItem/v1": hex.EncodeToString(sum[:16])}})
	}
	if rules == nil {
		rules = []rule{}
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "Hejnal", "version": toolVersion, "informationUri": "https://github.com/Legatia/hejnal", "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifRule(g match.Group) (id, name, help string) {
	f := g.Findings[0]
	switch g.Kind {
	case match.KindDependency:
		return f.Advisory, "vulnerable-dependency", "https://osv.dev/vulnerability/" + f.Advisory
	case match.KindMisconfig:
		return "iac/" + f.TechID, f.TechID, ""
	case match.KindSecret:
		return "secret/" + f.TechID, "secret", ""
	}
	return string(g.Kind) + "/" + f.TechID, string(g.Kind), ""
}

// sarifURI makes a finding's file a relative URI: an image's files are
// named after the image, whose name may hold a colon. url.PathEscape keeps
// colons, and "nginx:1.25:/var/..." would then read as a URI with the
// scheme "nginx", so colons are escaped too.
func sarifURI(file string) string {
	parts := strings.Split(file, "/")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(p), ":", "%3A")
	}
	return strings.TrimPrefix(strings.Join(parts, "/"), "/")
}

func sarifLevel(s match.Severity) string {
	switch s {
	case match.Critical, match.High:
		return "error"
	case match.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity is GitHub's 0–10 scale: 9 and up is critical, 7 high, 4
// medium.
func securitySeverity(s match.Severity) string {
	switch s {
	case match.Critical:
		return "9.5"
	case match.High:
		return "8.0"
	case match.Medium:
		return "5.5"
	}
	return "3.0"
}
