package match

import (
	"strings"
	"testing"
	"time"
)

func wordpress(cve string, score int) Finding {
	return Finding{Key: "kev|www.example.com|443|" + cve, Kind: KindKEV, Host: "www.example.com", Port: 443,
		TechID: "wordpress", Technology: "WordPress", CVE: cve, Score: score, Severity: SeverityFor(score),
		Confidence: ConfidenceProduct}
}

// acceptAll accepts the open findings of a group until the given day.
func acceptAll(g Group, until string) Acceptance {
	a := Acceptance{Item: g.ID(), Key: g.Key, Title: "WordPress on www.example.com:443", Reason: "Version 6.8.3 has the fixes",
		By: "Anna Nowak", AcceptedAt: now, Until: until}
	for _, f := range Active(g.Findings) {
		a.Findings = append(a.Findings, f.Key)
	}
	return a
}

func TestItemID(t *testing.T) {
	// The ID is the start of the key's SHA-256 hash, so it never changes.
	if got := ItemID("kev|127.0.0.1|18931|wordpress"); got != "4ad98b95" {
		t.Errorf("ItemID = %q, want 4ad98b95", got)
	}
	if h := ItemHash("kev|127.0.0.1|18931|wordpress"); len(h) != 64 || !strings.HasPrefix(h, "4ad98b95") {
		t.Errorf("ItemHash = %q", h)
	}
	// Every item of a run has its own ID, the same in the next run.
	first, second := Groups(run(t, nil)), Groups(run(t, nil))
	seen := map[string]string{}
	for i, g := range first {
		id := g.ID()
		if len(id) != 8 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Errorf("%s: ID %q is not 8 hexadecimal digits", g.Key, id)
		}
		if other, ok := seen[id]; ok {
			t.Errorf("%s and %s share the ID %s", g.Key, other, id)
		}
		seen[id] = g.Key
		if second[i].Key != g.Key || second[i].ID() != id {
			t.Errorf("item %s changed its ID between runs", g.Key)
		}
	}
}

func TestMarkAccepted(t *testing.T) {
	old1, old2 := wordpress("CVE-2026-87902", 75), wordpress("CVE-2026-60137", 70)
	item := Groups([]Finding{old1, old2})[0]
	a := acceptAll(item, "2027-02-02")

	fs := MarkAccepted([]Finding{old1, old2}, []Acceptance{a}, now)
	for _, f := range fs {
		if f.Accepted == nil || f.Accepted.Reason != a.Reason || f.Accepted.By != "Anna Nowak" || f.Accepted.Until != "2027-02-02" ||
			f.Accepted.Item != item.ID() || f.AcceptanceExpired != nil {
			t.Fatalf("%s: marks %+v %+v", f.Key, f.Accepted, f.AcceptanceExpired)
		}
		// A finding carries why it was accepted, not the whole record.
		if f.Accepted.Findings != nil || f.Accepted.Key != "" || f.Accepted.Title != "" {
			t.Errorf("%s carries the whole acceptance: %+v", f.Key, f.Accepted)
		}
	}
	if open := Open(fs); len(open) != 0 {
		t.Errorf("accepted findings are open: %v", open)
	}
	if old1.Accepted != nil {
		t.Error("MarkAccepted changed its input")
	}

	// A flaw that appears later in the same item is not covered: the item
	// comes back with the new flaw alone.
	fresh := wordpress("CVE-2026-119977", 85)
	fs = MarkAccepted([]Finding{fresh, old1, old2}, []Acceptance{a}, now)
	open := Groups(Open(fs))
	if len(open) != 1 || open[0].ID() != item.ID() || len(open[0].Findings) != 1 || open[0].Findings[0].CVE != "CVE-2026-119977" {
		t.Fatalf("open items after a new flaw = %+v", open)
	}
	if open[0].Severity != Critical || open[0].Acceptance() != nil {
		t.Errorf("the reopened item takes its severity from the new flaw only: %+v", open[0])
	}
	rest, accepted := SplitAccepted(fs)
	if len(rest) != 1 || len(accepted) != 2 {
		t.Errorf("split: %d rest, %d accepted", len(rest), len(accepted))
	}
	if g := Groups(accepted); len(g) != 1 || g[0].Acceptance().Until != "2027-02-02" || g[0].Key != item.Key {
		t.Errorf("accepted items = %+v", g)
	}

	// An acceptance holds through its last day and covers nothing after it.
	if fs := MarkAccepted([]Finding{old1}, []Acceptance{a}, time.Date(2027, 2, 2, 23, 59, 0, 0, time.UTC)); len(Open(fs)) != 0 {
		t.Error("the acceptance ended before its last day was over")
	}
	fs = MarkAccepted([]Finding{old1, old2}, []Acceptance{a}, time.Date(2027, 2, 3, 0, 0, 0, 0, time.UTC))
	if len(Open(fs)) != 2 || fs[0].Accepted != nil || fs[0].AcceptanceExpired == nil {
		t.Fatalf("after expiry: open %d, marks %+v %+v", len(Open(fs)), fs[0].Accepted, fs[0].AcceptanceExpired)
	}
	if g := Groups(fs)[0]; g.ExpiredAcceptance() == nil || g.ExpiredAcceptance().Until != "2027-02-02" || g.Acceptance() != nil {
		t.Errorf("expired item = %+v", g)
	}

	// Marking again replaces earlier marks.
	if fs := MarkAccepted(MarkAccepted([]Finding{old1}, []Acceptance{a}, now), nil, now); fs[0].Accepted != nil || fs[0].AcceptanceExpired != nil {
		t.Errorf("stale marks were kept: %+v", fs[0])
	}
	if MarkAccepted(nil, []Acceptance{a}, now) != nil {
		t.Error("MarkAccepted(nil) is not nil")
	}
}

func TestMarkAcceptedPrefersAnAcceptanceThatHolds(t *testing.T) {
	f := wordpress("CVE-2026-87902", 75)
	item := Groups([]Finding{f})[0]
	ended, holds := acceptAll(item, "2026-11-01"), acceptAll(item, "2026-12-01")
	holds.Reason = "Checked again"
	for _, as := range [][]Acceptance{{ended, holds}, {holds, ended}} {
		fs := MarkAccepted([]Finding{f}, as, now)
		if fs[0].Accepted == nil || fs[0].Accepted.Reason != "Checked again" || fs[0].AcceptanceExpired != nil {
			t.Errorf("marks = %+v, %+v", fs[0].Accepted, fs[0].AcceptanceExpired)
		}
	}
}

func TestAcceptedButRuledOut(t *testing.T) {
	f := wordpress("CVE-2026-87902", 75)
	a := acceptAll(Groups([]Finding{f})[0], "2027-02-02")
	f.Confidence, f.Score, f.Severity = ConfidenceRuledOut, 20, Low
	fs := MarkAccepted([]Finding{f}, []Acceptance{a}, now)
	rest, accepted := SplitAccepted(fs)
	if len(rest) != 1 || len(accepted) != 0 || len(Open(fs)) != 0 {
		t.Errorf("a ruled-out flaw should stay ruled out: rest %d, accepted %d, open %d", len(rest), len(accepted), len(Open(fs)))
	}
}

func TestAcceptanceCheck(t *testing.T) {
	good := acceptAll(Groups([]Finding{wordpress("CVE-2026-87902", 75)})[0], "2027-02-02")
	if err := good.Check(); err != nil {
		t.Fatalf("a good acceptance fails: %v", err)
	}
	for want, edit := range map[string]func(*Acceptance){
		"does not match its key": func(a *Acceptance) { a.Item = "00000000" },
		"no findings":            func(a *Acceptance) { a.Findings = nil },
		"until must be a date":   func(a *Acceptance) { a.Until = "2027-02-30" },
		"has no reason":          func(a *Acceptance) { a.Reason = "  " },
		"more than 500":          func(a *Acceptance) { a.Reason = strings.Repeat("ą", 501) },
		"more than 100":          func(a *Acceptance) { a.By = strings.Repeat("x", 101) },
		"control characters":     func(a *Acceptance) { a.Reason = "fine\n## Fake heading" },
	} {
		a := good
		edit(&a)
		if err := a.Check(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Check = %v, want an error containing %q", err, want)
		}
	}
	long := good
	long.Reason, long.By = strings.Repeat("ą", MaxReason), strings.Repeat("ł", MaxBy)
	if err := long.Check(); err != nil {
		t.Errorf("a reason and name at the limit fail: %v", err)
	}
}

func TestCleanNote(t *testing.T) {
	for in, want := range map[string]string{
		"  Version 6.8.3\nhas\tthe fix  ": "Version 6.8.3 has the fix",
		"a\u2028b\u202ec\x1b[31md":        "a b c [31md",
		"Łukasz Żółć":                     "Łukasz Żółć",
		"\n\t ":                           "",
	} {
		if got := CleanNote(in); got != want {
			t.Errorf("CleanNote(%q) = %q, want %q", in, got, want)
		}
	}
}
