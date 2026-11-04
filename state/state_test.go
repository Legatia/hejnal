package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
)

func TestInventoryRoundTrip(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), ".hejnal")}
	if _, err := s.LoadInventory(); !errors.Is(err, ErrNoInventory) {
		t.Fatalf("LoadInventory before the first run = %v", err)
	}
	inv := &inventory.Inventory{Organization: "Example", Assets: []inventory.Asset{{Host: "a.example.com"}}}
	if err := s.SaveInventory(inv); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadInventory()
	if err != nil || got.Organization != "Example" || len(got.Assets) != 1 {
		t.Fatalf("LoadInventory = %+v, %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(s.Dir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("inventory mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("state directory mode = %v, want 0700", di.Mode().Perm())
	}
}

func TestFindingsAndHistory(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.LoadFindings(); !errors.Is(err, ErrNoFindings) {
		t.Fatalf("LoadFindings before the first run = %v", err)
	}
	hist := filepath.Join(s.Dir, historyDir)
	if err := os.MkdirAll(hist, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < keepHistory+5; i++ {
		name := fmt.Sprintf("findings-2025%04dT000000Z.json", i)
		if err := os.WriteFile(filepath.Join(hist, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snap := &Snapshot{
		Organization: "Example",
		GeneratedAt:  time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Findings:     []match.Finding{{Key: "a"}},
	}
	if err := s.SaveFindings(snap); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadFindings()
	if err != nil || len(got.Findings) != 1 {
		t.Fatalf("LoadFindings = %+v, %v", got, err)
	}
	entries, err := os.ReadDir(hist)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != keepHistory {
		t.Errorf("history has %d files, want %d", len(entries), keepHistory)
	}
	if _, err := os.Stat(filepath.Join(hist, "findings-20261104T120000Z.json")); err != nil {
		t.Errorf("latest snapshot missing from history: %v", err)
	}
}

func TestReported(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if snap, err := s.LoadReported(); snap != nil || err != nil {
		t.Fatalf("LoadReported before anything was reported = %v, %v", snap, err)
	}
	if err := s.SaveReported(&Snapshot{Findings: []match.Finding{{Key: "a"}}}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.LoadReported()
	if err != nil || len(snap.Findings) != 1 {
		t.Fatalf("LoadReported = %+v, %v", snap, err)
	}
}

func TestDiff(t *testing.T) {
	prev := []match.Finding{{Key: "a"}, {Key: "b"}}
	cur := []match.Finding{{Key: "b"}, {Key: "c"}}
	added, resolved := Diff(prev, cur)
	if len(added) != 1 || added[0].Key != "c" {
		t.Errorf("added = %v", added)
	}
	if len(resolved) != 1 || resolved[0].Key != "a" {
		t.Errorf("resolved = %v", resolved)
	}
	added, resolved = Diff(nil, cur)
	if len(added) != 2 || len(resolved) != 0 {
		t.Errorf("first run: added %d resolved %d", len(added), len(resolved))
	}
}

func TestWriteFileReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x", "report.md")
	for _, body := range []string{"one", "two"} {
		if err := WriteFile(path, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "two" {
		t.Errorf("content = %q, %v", data, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}
