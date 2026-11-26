package state

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

const weeklyFile = "weekly.json"

type weeklyRecord struct {
	Sent time.Time `json:"sent"`
}

// WeeklySent returns when the last weekly summary was sent, or the zero time
// if none was.
func (s Store) WeeklySent() (time.Time, error) {
	var r weeklyRecord
	if err := readJSON(filepath.Join(s.Dir, weeklyFile), &r); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return r.Sent, nil
}

// SaveWeeklySent records when the weekly summary was sent.
func (s Store) SaveWeeklySent(t time.Time) error {
	return WriteJSON(filepath.Join(s.Dir, weeklyFile), weeklyRecord{Sent: t.UTC()})
}
