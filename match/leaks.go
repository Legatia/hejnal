package match

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Legatia/hejnal/leaks"
)

// secretScores rates secrets by the severity of the rule that found them:
// cloud keys and private keys are fixed now, other known tokens this week,
// and generic password assignments this month.
var secretScores = map[string]int{"critical": 90, "high": 80, "medium": 60}

// Secrets turns secrets found in source code into findings. Findings for the
// same secret form one item to fix, wherever it was found.
func Secrets(ls []leaks.Leak) []Finding {
	out := make([]Finding, 0, len(ls))
	for _, l := range ls {
		score, ok := secretScores[l.Severity]
		if !ok {
			score = 60
		}
		out = append(out, Finding{
			Key:         fmt.Sprintf("%s|%s|%s", KindSecret, l.Fingerprint, l.File),
			Kind:        KindSecret,
			TechID:      l.RuleID,
			Technology:  l.Description,
			Evidence:    l.Redacted,
			File:        cleanText(l.File),
			Line:        l.Line,
			Commit:      l.Commit,
			Fingerprint: l.Fingerprint,
			Score:       score,
			Severity:    SeverityFor(score),
			Confidence:  ConfidenceObserved,
		})
	}
	Sort(out)
	return out
}

// Breaches turns breach summaries into findings, one for each breach of
// each domain. A breach that exposed passwords and happened or became known
// in the last year is fixed this week, an older one this month. Breaches
// without passwords come later, and spam lists, which hold only addresses,
// last.
func Breaches(sums []leaks.DomainSummary, now time.Time) []Finding {
	var out []Finding
	for _, d := range sums {
		for _, b := range d.Breaches {
			score := 40
			switch {
			case b.Passwords && (withinYear(b.BreachDate, now) || withinYear(b.AddedDate, now)):
				score = 70
			case b.Passwords:
				score = 55
			case b.SpamList:
				score = 30
			}
			out = append(out, Finding{
				Key:         fmt.Sprintf("%s|%s|%s", KindBreach, d.Domain, b.Name),
				Kind:        KindBreach,
				Host:        d.Domain,
				TechID:      b.Name,
				Name:        b.Title,
				BreachDate:  validDate(b.BreachDate),
				DateAdded:   validDate(b.AddedDate),
				Description: strings.Join(b.DataClasses, ", "),
				Accounts:    b.Accounts,
				Passwords:   b.Passwords,
				Score:       score,
				Severity:    SeverityFor(score),
				Confidence:  ConfidenceObserved,
			})
		}
	}
	Sort(out)
	return out
}

// validDate returns a YYYY-MM-DD date, or "" for anything else, so breach
// data cannot inject text where reports expect a date.
func validDate(s string) string {
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return ""
	}
	return s
}

// withinYear reports whether a YYYY-MM-DD date is less than a year before now.
func withinYear(date string, now time.Time) bool {
	t, err := time.Parse("2006-01-02", date)
	return err == nil && now.Sub(t) < 365*24*time.Hour
}

// cleanText replaces control characters and line separators, so a file name
// saved by an older version cannot add lines to reports and messages.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return '?'
		}
		return r
	}, s)
}
