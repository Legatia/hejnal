package state

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
)

func acceptance() match.Acceptance {
	key := "kev|www.example.com|443|wordpress"
	return match.Acceptance{
		Item:       match.ItemID(key),
		Key:        key,
		Title:      "WordPress on www.example.com:443",
		Findings:   []string{"kev|www.example.com|443|CVE-2026-87902"},
		Reason:     "Version 6.8.3 has the fix",
		By:         "Anna Nowak",
		AcceptedAt: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Until:      "2027-02-02",
	}
}

func TestAccepted(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if as, err := s.LoadAccepted(); as != nil || err != nil {
		t.Fatalf("before saving: %v, %v", as, err)
	}
	a := acceptance()
	if err := s.SaveAccepted([]match.Acceptance{a}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadAccepted()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], a) {
		t.Fatalf("LoadAccepted = %+v, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(filepath.Join(s.Dir, AcceptedFile)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, mode %v", AcceptedFile, err, st.Mode())
		}
	}

	// Saved acceptances apply to findings straight away.
	snap := &Snapshot{Findings: []match.Finding{{Key: a.Findings[0], Kind: match.KindKEV, Confidence: match.ConfidenceProduct}}}
	if err := s.MarkAccepted(snap, a.AcceptedAt); err != nil || snap.Findings[0].Accepted == nil {
		t.Errorf("MarkAccepted: %v, %+v", err, snap.Findings[0])
	}

	// An acceptance without a reason is never saved.
	bad := a
	bad.Reason = ""
	if err := s.SaveAccepted([]match.Acceptance{bad}); err == nil {
		t.Error("an acceptance without a reason was saved")
	}
	if err := s.SaveAccepted(nil); err != nil {
		t.Fatal(err)
	}
	if as, err := s.LoadAccepted(); len(as) != 0 || err != nil {
		t.Errorf("after saving none: %v, %v", as, err)
	}
}

func TestLoadAcceptedRejectsBadFiles(t *testing.T) {
	a := acceptance()
	good := `{"accepted": [{"item": "` + a.Item + `", "key": "` + a.Key + `", "findings": ["` + a.Findings[0] +
		`"], "reason": "Version 6.8.3 has the fix", "acceptedAt": "2026-11-04T12:00:00Z", "until": "2027-02-02"}]}`
	for want, data := range map[string]string{
		"":                       good,
		"unknown field":          strings.Replace(good, `"until"`, `"expires"`, 1),
		"unknown field \"note\"": strings.Replace(good, `{"accepted"`, `{"note": "x", "accepted"`, 1),
		"unexpected data":        good + `{}`,
		"until must be a date":   strings.Replace(good, `"2027-02-02"`, `"soon"`, 1),
		"does not match":         strings.Replace(good, a.Item, "00000000", 1),
		"control characters":     strings.Replace(good, "has the fix", `has the fix\n# Fake`, 1),
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, AcceptedFile), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		as, err := Store{Dir: dir}.LoadAccepted()
		switch {
		case want == "" && (err != nil || len(as) != 1):
			t.Errorf("good file: %v, %v", as, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), AcceptedFile)):
			t.Errorf("want an error about %s containing %q, got %v", AcceptedFile, want, err)
		}
	}
}
