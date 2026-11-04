package engine

import (
	"context"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// acceptGroup accepts the open findings of a group until the given day.
func acceptGroup(g match.Group, until string) match.Acceptance {
	a := match.Acceptance{Item: g.ID(), Key: g.Key, Reason: "Version 6.8.3 has the fix", AcceptedAt: testNow, Until: until}
	for _, f := range match.Active(g.Findings) {
		a.Findings = append(a.Findings, f.Key)
	}
	return a
}

func TestChangesLeaveOutAcceptedFindings(t *testing.T) {
	e, err := New(Config{StateDir: t.TempDir(), NoEPSS: true, NoCT: true, NoNVD: true})
	if err != nil {
		t.Fatal(err)
	}
	f := match.Finding{Key: "kev|w|443|CVE-2026-87902", Kind: match.KindKEV, Host: "w", Port: 443, TechID: "wordpress",
		CVE: "CVE-2026-87902", Score: 75, Severity: match.High, Confidence: match.ConfidenceProduct}
	acc := acceptGroup(match.Groups([]match.Finding{f})[0], "2026-12-01")
	accepted := match.MarkAccepted([]match.Finding{f}, []match.Acceptance{acc}, testNow)

	// Before anything was reported, an accepted finding is not new.
	ch, err := e.Changes(&state.Snapshot{Findings: accepted})
	if err != nil || !ch.First || len(ch.Added) != 0 {
		t.Fatalf("first changes: %+v, %v", ch, err)
	}
	// Accepting a reported finding does not resolve it.
	if err := e.MarkReported(&state.Snapshot{Findings: []match.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if ch, _ = e.Changes(&state.Snapshot{Findings: accepted}); len(ch.Added) != 0 || len(ch.Resolved) != 0 {
		t.Errorf("after accepting: added %d, resolved %d; want 0 and 0", len(ch.Added), len(ch.Resolved))
	}
	// Once the acceptance expires, the finding is open, and news, again.
	if err := e.MarkReported(&state.Snapshot{Findings: accepted}); err != nil {
		t.Fatal(err)
	}
	expired := match.MarkAccepted([]match.Finding{f}, []match.Acceptance{acc}, time.Date(2026, 12, 2, 7, 0, 0, 0, time.UTC))
	ch, _ = e.Changes(&state.Snapshot{Findings: expired})
	if len(ch.Added) != 1 || ch.Added[0].AcceptanceExpired == nil || len(ch.Resolved) != 0 {
		t.Errorf("after expiry: added %+v, resolved %d; want the finding and 0", ch.Added, len(ch.Resolved))
	}
	// An accepted finding that is gone is resolved.
	if ch, _ = e.Changes(&state.Snapshot{}); len(ch.Resolved) != 1 || len(ch.Added) != 0 {
		t.Errorf("accepted finding gone: added %d, resolved %d; want 0 and 1", len(ch.Added), len(ch.Resolved))
	}
}

func TestMatchMarksAcceptedFindings(t *testing.T) {
	e, err := New(Config{StateDir: t.TempDir(), KEVFile: "../testdata/kev_sample.json", NoEPSS: true, NoCT: true, NoNVD: true,
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{Organization: "Test", Assets: []inventory.Asset{{Host: "www.example.com", Services: []inventory.Service{{
		Port: 443, Scheme: "https", URL: "https://www.example.com/",
		Technologies: []inventory.Technology{{ID: "wordpress", Name: "WordPress", Category: "cms"}},
	}}}}}
	snap, err := e.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	gs := match.Groups(snap.Findings)
	if len(gs) != 1 || len(gs[0].Findings) != 2 {
		t.Fatalf("items = %+v", gs)
	}
	if err := e.Store().SaveAccepted([]match.Acceptance{acceptGroup(gs[0], "2027-02-02")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Match(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	saved, err := e.Store().LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range saved.Findings {
		if f.Accepted == nil || f.Accepted.Until != "2027-02-02" || f.Accepted.Reason != "Version 6.8.3 has the fix" {
			t.Errorf("%s is not marked accepted in the saved findings: %+v", f.Key, f.Accepted)
		}
	}
}
