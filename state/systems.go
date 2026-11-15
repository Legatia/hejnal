package state

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Legatia/hejnal/inventory"
)

const (
	systemsFile = "systems.json"
	// systemChangesFile keeps the changes among the services seen that
	// people have not been told about yet: for keepChanges at most, and
	// maxChanges of each kind, when nothing marks them as reported, as with
	// the REST API alone.
	systemChangesFile = "system-changes.json"
	keepChanges       = 90 * 24 * time.Hour
	maxChanges        = 500
)

// SaveSystems stores the record of every service seen.
func (s Store) SaveSystems(rs []inventory.Record) error {
	if rs == nil {
		rs = []inventory.Record{}
	}
	return WriteJSON(filepath.Join(s.Dir, systemsFile), rs)
}

// LoadSystems reads the record of every service seen. It returns nil before
// the first discovery run.
func (s Store) LoadSystems() ([]inventory.Record, error) {
	var rs []inventory.Record
	if err := readJSON(filepath.Join(s.Dir, systemsFile), &rs); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return rs, nil
}

// AddSystemChanges keeps changes among the services seen, found at now,
// until people are told about them, after the ones kept already.
func (s Store) AddSystemChanges(ch inventory.Changes, now time.Time) error {
	if ch.Empty() {
		return nil
	}
	all, err := s.SystemChanges()
	if err != nil {
		return err
	}
	all.Add(ch)
	all.Trim(now, keepChanges, maxChanges)
	return WriteJSON(filepath.Join(s.Dir, systemChangesFile), all)
}

// SystemChanges returns the changes among the services seen that people
// have not been told about.
func (s Store) SystemChanges() (inventory.Changes, error) {
	var ch inventory.Changes
	if err := readJSON(filepath.Join(s.Dir, systemChangesFile), &ch); err != nil && !errors.Is(err, os.ErrNotExist) {
		return inventory.Changes{}, err
	}
	return ch, nil
}

// ClearSystemChanges forgets the changes people have been told about.
func (s Store) ClearSystemChanges() error {
	if err := os.Remove(filepath.Join(s.Dir, systemChangesFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
