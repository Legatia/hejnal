package match

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The longest reason and name an acceptance may hold, in characters.
const (
	MaxReason = 500
	MaxBy     = 100
)

// Acceptance records that a person checked an item to fix and accepted it
// for a while: the version running has the fix, say, or the service cannot be
// reached from the internet. It covers the findings open in the item when it
// was accepted, and nothing that appears in the item later. After Until it
// covers nothing.
//
// On a finding, an Acceptance says who accepted it, why and until when; its
// Key, Title and Findings are then empty.
type Acceptance struct {
	// Item is the item's ID, as the fix list shows it.
	Item string `json:"item"`
	// Key is the item's group key, and Title names the item for people.
	Key   string `json:"key,omitempty"`
	Title string `json:"title,omitempty"`
	// Findings are the keys of the findings the acceptance covers.
	Findings []string `json:"findings,omitempty"`
	// Reason says why the item needs no action, and By who checked it.
	// People type them, so escape them wherever they are shown.
	Reason string `json:"reason"`
	By     string `json:"by,omitempty"`
	// AcceptedAt is when the item was accepted. Until is the last day the
	// acceptance holds, as YYYY-MM-DD in UTC.
	AcceptedAt time.Time `json:"acceptedAt"`
	Until      string    `json:"until"`
}

// ItemHash returns the SHA-256 hash of an item's group key in hexadecimal.
// Its first 8 digits are the item's ID; more of them tell apart two items
// whose IDs happen to be the same.
func ItemHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// ItemID returns the short ID of the item with the given group key. It stays
// the same across runs, so people can name an item and accept it.
func ItemID(key string) string { return ItemHash(key)[:8] }

// ID returns the group's item ID.
func (g Group) ID() string { return ItemID(g.Key) }

// Expired reports whether the acceptance no longer holds at now.
func (a Acceptance) Expired(now time.Time) bool {
	return a.Until < now.UTC().Format("2006-01-02")
}

// Check reports whether a saved acceptance is complete and well formed.
func (a Acceptance) Check() error {
	switch {
	case a.Key == "" || a.Item != ItemID(a.Key):
		return fmt.Errorf("item %q does not match its key %q", a.Item, a.Key)
	case len(a.Findings) == 0:
		return fmt.Errorf("item %s covers no findings", a.Item)
	case validDate(a.Until) == "":
		return fmt.Errorf("item %s: until must be a date such as 2027-02-01, not %q", a.Item, a.Until)
	case strings.TrimSpace(a.Reason) == "":
		return fmt.Errorf("item %s has no reason", a.Item)
	}
	if err := checkNote("reason", a.Reason, MaxReason); err != nil {
		return fmt.Errorf("item %s: %w", a.Item, err)
	}
	if err := checkNote("name", a.By, MaxBy); err != nil {
		return fmt.Errorf("item %s: %w", a.Item, err)
	}
	return nil
}

func checkNote(name, s string, limit int) error {
	if n := utf8.RuneCountInString(s); n > limit {
		return fmt.Errorf("the %s is %d characters long, more than %d", name, n, limit)
	}
	if strings.IndexFunc(s, hidden) >= 0 {
		return fmt.Errorf("the %s holds control characters", name)
	}
	return nil
}

// hidden reports whether r is a control character, a line or paragraph
// separator or a text-direction control: characters that can break a line of
// a report or disguise what it says.
func hidden(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069'
}

// CleanNote tidies text a person typed, such as a reason: control
// characters, line breaks and text-direction controls become spaces, and runs
// of spaces become one.
func CleanNote(s string) string {
	s = strings.Map(func(r rune) rune {
		if hidden(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// MarkAccepted returns a copy of the findings, marked with the acceptances
// that cover them at now: Accepted while an acceptance holds, and
// AcceptanceExpired once it has ended. Marks from earlier calls are replaced.
func MarkAccepted(fs []Finding, as []Acceptance, now time.Time) []Finding {
	if fs == nil {
		return nil
	}
	// For each finding, the acceptance that holds longest, and the expired
	// one that ended last.
	holds, ended := map[string]*Acceptance{}, map[string]*Acceptance{}
	for i := range as {
		a := &as[i]
		m := holds
		if a.Expired(now) {
			m = ended
		}
		for _, k := range a.Findings {
			if b, ok := m[k]; !ok || a.Until > b.Until {
				m[k] = a
			}
		}
	}
	out := make([]Finding, len(fs))
	for i, f := range fs {
		f.Accepted, f.AcceptanceExpired = nil, nil
		if a, ok := holds[f.Key]; ok {
			f.Accepted = a.onFinding()
		} else if a, ok := ended[f.Key]; ok {
			f.AcceptanceExpired = a.onFinding()
		}
		out[i] = f
	}
	return out
}

// onFinding returns the acceptance as a finding carries it: without the
// item's key, title and findings.
func (a Acceptance) onFinding() *Acceptance {
	return &Acceptance{Item: a.Item, Reason: a.Reason, By: a.By, AcceptedAt: a.AcceptedAt, Until: a.Until}
}

// Open returns the findings that need attention: those the version check
// does not rule out and nobody has accepted.
func Open(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if !f.RuledOut() && f.Accepted == nil {
			out = append(out, f)
		}
	}
	return out
}

// SplitAccepted separates the accepted findings from the rest, so reports can
// list them apart. An accepted finding the version check now rules out stays
// with the rest, as ruled out.
func SplitAccepted(fs []Finding) (rest, accepted []Finding) {
	for _, f := range fs {
		if f.Accepted != nil && !f.RuledOut() {
			accepted = append(accepted, f)
		} else {
			rest = append(rest, f)
		}
	}
	return rest, accepted
}

// Acceptance returns the acceptance of the group's accepted findings, the one
// that ends first if there are several, or nil if none is accepted.
func (g Group) Acceptance() *Acceptance {
	var out *Acceptance
	for _, f := range g.Findings {
		if a := f.Accepted; a != nil && (out == nil || a.Until < out.Until) {
			out = a
		}
	}
	return out
}

// ExpiredAcceptance returns the acceptance that covered the group's findings
// and has expired, the one that ended last if there are several, or nil.
func (g Group) ExpiredAcceptance() *Acceptance {
	var out *Acceptance
	for _, f := range g.Findings {
		if a := f.AcceptanceExpired; a != nil && (out == nil || a.Until > out.Until) {
			out = a
		}
	}
	return out
}
