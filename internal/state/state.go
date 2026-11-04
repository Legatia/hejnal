// Package state keeps Hejnal's results between runs in a local directory, so
// each run can say what is new and what has been fixed.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Legatia/hejnal/internal/inventory"
	"github.com/Legatia/hejnal/internal/match"
)

const (
	inventoryFile = "inventory.json"
	findingsFile  = "findings.json"
	reportedFile  = "reported.json"
	historyDir    = "history"
	// keepHistory is how many past findings snapshots are kept.
	keepHistory = 200
)

// ErrNoInventory is returned before the first discovery run.
var ErrNoInventory = errors.New("no inventory yet: run `hejnal discover` or `hejnal run` first")

// ErrNoFindings is returned before the first match run.
var ErrNoFindings = errors.New("no findings yet: run `hejnal match` or `hejnal run` first")

// Store is a state directory. Files are readable only by their owner because
// an inventory is a map of the organisation's attack surface.
type Store struct {
	Dir string
}

// Snapshot is the result of one match run.
type Snapshot struct {
	Organization string          `json:"organization"`
	GeneratedAt  time.Time       `json:"generatedAt"`
	KEVVersion   string          `json:"kevVersion,omitempty"`
	EPSSDate     string          `json:"epssDate,omitempty"`
	Findings     []match.Finding `json:"findings"`
}

// SaveInventory stores the latest inventory.
func (s Store) SaveInventory(inv *inventory.Inventory) error {
	return WriteJSON(filepath.Join(s.Dir, inventoryFile), inv)
}

// LoadInventory reads the latest inventory.
func (s Store) LoadInventory() (*inventory.Inventory, error) {
	var inv inventory.Inventory
	if err := readJSON(filepath.Join(s.Dir, inventoryFile), &inv); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoInventory
		}
		return nil, err
	}
	return &inv, nil
}

// SaveFindings stores a snapshot as the latest one and in the history.
func (s Store) SaveFindings(snap *Snapshot) error {
	if err := WriteJSON(filepath.Join(s.Dir, findingsFile), snap); err != nil {
		return err
	}
	name := "findings-" + snap.GeneratedAt.UTC().Format("20060102T150405Z") + ".json"
	if err := WriteJSON(filepath.Join(s.Dir, historyDir, name), snap); err != nil {
		return err
	}
	return s.prune()
}

// LoadFindings reads the latest snapshot. It returns ErrNoFindings before the
// first run.
func (s Store) LoadFindings() (*Snapshot, error) {
	var snap Snapshot
	if err := readJSON(filepath.Join(s.Dir, findingsFile), &snap); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoFindings
		}
		return nil, err
	}
	return &snap, nil
}

// SaveReported records the findings people were last told about, on screen
// or in chat. The next run reports what changed since then, so findings are
// not lost when a notification fails.
func (s Store) SaveReported(snap *Snapshot) error {
	return WriteJSON(filepath.Join(s.Dir, reportedFile), snap)
}

// LoadReported reads the findings people were last told about. It returns
// nil before anything was reported.
func (s Store) LoadReported() (*Snapshot, error) {
	var snap Snapshot
	if err := readJSON(filepath.Join(s.Dir, reportedFile), &snap); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &snap, nil
}

func (s Store) prune() error {
	dir := filepath.Join(s.Dir, historyDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "findings-") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	for len(names) > keepHistory {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			return err
		}
		names = names[1:]
	}
	return nil
}

// Diff compares two runs by finding key.
func Diff(prev, cur []match.Finding) (added, resolved []match.Finding) {
	before := map[string]bool{}
	for _, f := range prev {
		before[f.Key] = true
	}
	now := map[string]bool{}
	for _, f := range cur {
		now[f.Key] = true
		if !before[f.Key] {
			added = append(added, f)
		}
	}
	for _, f := range prev {
		if !now[f.Key] {
			resolved = append(resolved, f)
		}
	}
	return added, resolved
}

// WriteJSON writes v as indented JSON, atomically and readable only by the
// owner.
func WriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(data, '\n'))
}

// WriteFile writes data atomically: a crash never leaves a half-written file.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
