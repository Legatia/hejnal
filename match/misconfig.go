package match

import (
	"fmt"

	"github.com/Legatia/hejnal/iac"
)

// Misconfigs turns settings in infrastructure code into findings, one per
// setting.
func Misconfigs(project string, issues []iac.Issue) []Finding {
	out := make([]Finding, 0, len(issues))
	for _, i := range issues {
		score, ok := iac.Scores[i.Rule]
		if !ok {
			score = 50
		}
		f := Finding{
			Kind:       KindMisconfig,
			Host:       cleanText(project),
			TechID:     i.Rule,
			Technology: cleanText(i.Resource),
			Evidence:   cleanText(i.Detail),
			File:       cleanText(i.File),
			Line:       i.Line,
			Score:      score,
			Severity:   SeverityFor(score),
			Confidence: ConfidenceObserved,
		}
		f.Key = fmt.Sprintf("%s|%s|%s|%s|%s|%s", KindMisconfig, f.Host, f.File, i.Rule, f.Technology, f.Evidence)
		out = append(out, f)
	}
	Sort(out)
	return out
}
