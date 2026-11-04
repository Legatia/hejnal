package leaks

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// DomainSummary is the result of a domain search, ready to store or report.
type DomainSummary struct {
	Domain string `json:"domain"`
	// Accounts is the number of unique addresses on the domain found in at
	// least one breach.
	Accounts int `json:"accounts"`
	// Breaches are sorted newest first.
	Breaches []DomainBreach `json:"breaches"`
	// Aliases are the parts before the @ of the affected addresses, in lower
	// case and sorted. They identify people, so they are personal data: the
	// caller decides whether to store or show them. WithoutAliases drops
	// them.
	Aliases []string `json:"aliases,omitempty"`
}

// DomainBreach is one breach that affected accounts on the domain.
type DomainBreach struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// BreachDate is when the breach happened and AddedDate when HIBP added
	// it, both as YYYY-MM-DD. They are empty when unknown.
	BreachDate  string   `json:"breachDate"`
	AddedDate   string   `json:"addedDate"`
	DataClasses []string `json:"dataClasses"`
	// Accounts is how many addresses on the domain were in this breach.
	Accounts int `json:"accounts"`
	// Passwords reports whether the breach exposed passwords, that is,
	// whether its data classes include "Passwords".
	Passwords bool `json:"passwords"`
	// SpamList reports whether HIBP marks the source as a spam list rather
	// than a breach of a service.
	SpamList bool `json:"spamList"`
}

// Summarise combines the result of HIBP.BreachedDomain with breach details
// from HIBP.Breach, keyed by breach name. A breach missing from breaches is
// still listed, by name only.
func Summarise(domain string, accounts map[string][]string, breaches map[string]Breach) DomainSummary {
	s := DomainSummary{Domain: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")}

	// HIBP sends each alias once, but merge aliases that differ only in case
	// so that no account is counted twice.
	byAlias := map[string]map[string]bool{}
	for alias, names := range accounts {
		alias = strings.ToLower(strings.TrimSpace(alias))
		for _, n := range names {
			if n = strings.TrimSpace(n); n == "" || alias == "" {
				continue
			}
			if byAlias[alias] == nil {
				byAlias[alias] = map[string]bool{}
			}
			byAlias[alias][n] = true
		}
	}
	counts := map[string]int{}
	for alias, names := range byAlias {
		s.Aliases = append(s.Aliases, alias)
		for n := range names {
			counts[n]++
		}
	}
	slices.Sort(s.Aliases)
	s.Accounts = len(s.Aliases)

	s.Breaches = make([]DomainBreach, 0, len(counts))
	for name, n := range counts {
		b := breaches[name]
		s.Breaches = append(s.Breaches, DomainBreach{
			Name:        name,
			Title:       cmp.Or(b.Title, name),
			BreachDate:  day(b.BreachDate),
			AddedDate:   day(b.AddedDate),
			DataClasses: append([]string{}, b.DataClasses...),
			Accounts:    n,
			Passwords:   slices.ContainsFunc(b.DataClasses, func(c string) bool { return strings.EqualFold(c, "Passwords") }),
			SpamList:    b.IsSpamList,
		})
	}
	slices.SortFunc(s.Breaches, func(a, b DomainBreach) int {
		if (a.BreachDate == "") != (b.BreachDate == "") {
			if a.BreachDate == "" {
				return 1 // unknown dates last
			}
			return -1
		}
		return cmp.Or(strings.Compare(b.BreachDate, a.BreachDate), cmp.Compare(b.Accounts, a.Accounts), strings.Compare(a.Name, b.Name))
	})
	return s
}

// WithoutAliases returns a copy of d without the aliases, for storing a
// summary that does not identify people.
func (d DomainSummary) WithoutAliases() DomainSummary {
	d.Aliases = nil
	d.Breaches = slices.Clone(d.Breaches)
	for i := range d.Breaches {
		d.Breaches[i].DataClasses = slices.Clone(d.Breaches[i].DataClasses)
	}
	return d
}

// day turns an HIBP date or timestamp, such as "2013-12-04T00:00:00Z", into
// YYYY-MM-DD. It returns "" for anything else.
func day(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 10 {
		return ""
	}
	if _, err := time.Parse(time.DateOnly, s[:10]); err != nil {
		return ""
	}
	return s[:10]
}
