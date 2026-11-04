package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Legatia/hejnal/match"
)

// AcceptedFile keeps the items people accepted with `hejnal accept`.
const AcceptedFile = "accepted.json"

// accepted is the layout of AcceptedFile.
type accepted struct {
	Accepted []match.Acceptance `json:"accepted"`
}

// LoadAccepted reads the saved acceptances. It returns none if there are
// none. Unknown fields are rejected, so a misspelt key cannot silently change
// what is accepted.
func (s Store) LoadAccepted() ([]match.Acceptance, error) {
	path := filepath.Join(s.Dir, AcceptedFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var file accepted
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: unexpected data after the accepted items", path)
	}
	for _, a := range file.Accepted {
		if err := a.Check(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return file.Accepted, nil
}

// SaveAccepted stores the acceptances, replacing the saved ones.
func (s Store) SaveAccepted(as []match.Acceptance) error {
	for _, a := range as {
		if err := a.Check(); err != nil {
			return err
		}
	}
	if as == nil {
		as = []match.Acceptance{}
	}
	return WriteJSON(filepath.Join(s.Dir, AcceptedFile), accepted{Accepted: as})
}

// MarkAccepted marks the snapshot's findings with the saved acceptances that
// cover them at now, so an acceptance applies as soon as it is made. See
// match.MarkAccepted.
func (s Store) MarkAccepted(snap *Snapshot, now time.Time) error {
	as, err := s.LoadAccepted()
	if err != nil {
		return err
	}
	snap.Findings = match.MarkAccepted(snap.Findings, as, now)
	return nil
}
