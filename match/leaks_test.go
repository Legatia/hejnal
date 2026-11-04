package match

import (
	"testing"
	"time"

	"github.com/Legatia/hejnal/leaks"
)

func TestSecrets(t *testing.T) {
	ls := []leaks.Leak{
		{RuleID: "github-pat", Description: "GitHub personal access token", Severity: "critical", File: "web/app.py",
			Line: 3, Redacted: "ghp_ab… (40 chars)", Fingerprint: "00112233aabbccdd"},
		{RuleID: "github-pat", Description: "GitHub personal access token", Severity: "critical", File: "web/old.py",
			Line: 9, Commit: "8f2c1d0e9b7a6f5e", Redacted: "ghp_ab… (40 chars)", Fingerprint: "00112233aabbccdd"},
		{RuleID: "generic-password", Description: "Password in code", Severity: "medium", File: "api/settings.py",
			Line: 12, Redacted: "Zx9q… (14 chars)", Fingerprint: "ffeeddccbbaa9988"},
	}
	fs := Secrets(ls)
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3", len(fs))
	}
	gs := Groups(fs)
	if len(gs) != 2 {
		t.Fatalf("got %d items, want 2 (one per secret)", len(gs))
	}
	if g := gs[0]; g.Key != "secret|00112233aabbccdd" || g.Severity != Critical || len(g.Findings) != 2 || g.Port != 0 {
		t.Errorf("first item = %+v", g)
	}
	if g := gs[1]; g.Severity != Medium || g.Findings[0].File != "api/settings.py" || g.Findings[0].Line != 12 {
		t.Errorf("second item = %+v", g)
	}
	if fs[1].Key == fs[0].Key {
		t.Error("the same secret in two files must be two findings")
	}
}

func TestBreaches(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	sums := []leaks.DomainSummary{{Domain: "example.com", Accounts: 9, Breaches: []leaks.DomainBreach{
		{Name: "Recent", Title: "Recent", BreachDate: "2026-06-01", AddedDate: "2026-07-01", Accounts: 3, Passwords: true},
		{Name: "OldButNewlyKnown", Title: "Old but newly known", BreachDate: "2019-01-01", AddedDate: "2026-10-01", Accounts: 1, Passwords: true},
		{Name: "Adobe", Title: "Adobe", BreachDate: "2013-10-04", AddedDate: "2013-12-04", Accounts: 5, Passwords: true,
			DataClasses: []string{"Email addresses", "Passwords"}},
		{Name: "NoPasswords", Title: "No passwords", BreachDate: "2025-01-01", AddedDate: "2025-02-01", Accounts: 2},
		{Name: "Spam", Title: "Spam list", BreachDate: "2020-01-01", AddedDate: "2020-01-02", Accounts: 4, SpamList: true},
	}}}
	fs := Breaches(sums, now)
	want := map[string]int{"Recent": 70, "OldButNewlyKnown": 70, "Adobe": 55, "NoPasswords": 40, "Spam": 30}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d", len(fs), len(want))
	}
	for _, f := range fs {
		if f.Score != want[f.TechID] || f.Host != "example.com" || f.Kind != KindBreach {
			t.Errorf("%s: score %d, host %q, kind %q", f.TechID, f.Score, f.Host, f.Kind)
		}
		if f.TechID == "Adobe" && (f.Description != "Email addresses, Passwords" || f.Accounts != 5 || f.BreachDate != "2013-10-04") {
			t.Errorf("Adobe finding = %+v", f)
		}
	}
	gs := Groups(fs)
	if len(gs) != 1 || gs[0].Key != "breach|example.com" || gs[0].Severity != High || len(gs[0].Findings) != 5 {
		t.Errorf("groups = %+v", gs)
	}
}
