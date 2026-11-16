package state

import (
	"testing"
	"time"

	"github.com/Legatia/hejnal/inventory"
)

func TestSystemsAndTheirChanges(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if rs, err := s.LoadSystems(); err != nil || rs != nil {
		t.Fatalf("before the first run: %v, %v", rs, err)
	}
	now := time.Date(2026, 11, 4, 6, 0, 0, 0, time.UTC)
	rs := []inventory.Record{{Host: "shop.example.com", Port: 443, FirstSeen: now, LastSeen: now}}
	if err := s.SaveSystems(rs); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LoadSystems(); err != nil || len(got) != 1 || got[0].Host != "shop.example.com" {
		t.Fatalf("loaded %+v, %v", got, err)
	}

	if ch, err := s.SystemChanges(); err != nil || !ch.Empty() {
		t.Fatalf("changes before any: %+v, %v", ch, err)
	}
	if err := s.AddSystemChanges(inventory.Changes{New: rs}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSystemChanges(inventory.Changes{Gone: []inventory.Gone{{Record: rs[0]}}}, now); err != nil {
		t.Fatal(err)
	}
	ch, err := s.SystemChanges()
	if err != nil || len(ch.New) != 1 || len(ch.Gone) != 1 {
		t.Fatalf("kept changes %+v, %v", ch, err)
	}
	if err := s.ClearSystemChanges(); err != nil {
		t.Fatal(err)
	}
	if ch, err := s.SystemChanges(); err != nil || !ch.Empty() {
		t.Errorf("after clearing: %+v, %v", ch, err)
	}
	if err := s.ClearSystemChanges(); err != nil {
		t.Errorf("clearing twice: %v", err)
	}

	// Changes nobody collects do not pile up.
	later := now.Add(keepChanges + time.Hour)
	if err := s.AddSystemChanges(inventory.Changes{New: rs}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSystemChanges(inventory.Changes{Updated: []inventory.VersionChange{{Host: "shop.example.com", At: later}}}, later); err != nil {
		t.Fatal(err)
	}
	if ch, err := s.SystemChanges(); err != nil || len(ch.New) != 0 || len(ch.Updated) != 1 {
		t.Errorf("old changes kept: %+v, %v", ch, err)
	}
}
