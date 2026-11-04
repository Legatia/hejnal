package state

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Legatia/hejnal/leaks"
)

// Files that keep leak results between runs.
const (
	LeaksFile    = "leaks.json"
	BreachesFile = "breaches.json"
	// LeakKeyFile holds the key for secret fingerprints.
	LeakKeyFile = "leaks.key"
)

// LeakKey returns the key that makes secret fingerprints keyed hashes,
// creating it on first use. With the key kept private, a fingerprint shown
// in reports, the API or the MCP server cannot be checked against guesses.
func (s Store) LeakKey() ([]byte, error) {
	path := filepath.Join(s.Dir, LeakKeyFile)
	key, err := os.ReadFile(path)
	if err == nil && len(key) == 32 {
		return key, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := WriteFile(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// LeakScan is a saved scan of source code for secrets. Secrets are kept only
// partly hidden, as the leaks package reports them.
type LeakScan struct {
	ScannedAt time.Time    `json:"scannedAt"`
	Roots     []string     `json:"roots"`
	History   bool         `json:"history"`
	Leaks     []leaks.Leak `json:"leaks"`
}

// BreachCheck is a saved check of the organisation's domains against known
// data breaches. It holds counts only, never account names.
type BreachCheck struct {
	CheckedAt time.Time             `json:"checkedAt"`
	Domains   []leaks.DomainSummary `json:"domains"`
}

// SaveLeakScan stores a secret scan, replacing the previous one.
func (s Store) SaveLeakScan(scan *LeakScan) error {
	return WriteJSON(filepath.Join(s.Dir, LeaksFile), scan)
}

// LoadLeakScan reads the saved secret scan. It returns nil if there is none.
func (s Store) LoadLeakScan() (*LeakScan, error) {
	var scan LeakScan
	if err := readJSON(filepath.Join(s.Dir, LeaksFile), &scan); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &scan, nil
}

// SaveBreachCheck stores a breach check, replacing the previous one.
func (s Store) SaveBreachCheck(check *BreachCheck) error {
	return WriteJSON(filepath.Join(s.Dir, BreachesFile), check)
}

// LoadBreachCheck reads the saved breach check. It returns nil if there is
// none.
func (s Store) LoadBreachCheck() (*BreachCheck, error) {
	var check BreachCheck
	if err := readJSON(filepath.Join(s.Dir, BreachesFile), &check); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &check, nil
}
