package state

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

const weeklyFile = "weekly.json"

// MaxWeeks is how many weekly summaries' numbers are kept: two years.
const MaxWeeks = 104

// Week holds the numbers of one weekly summary, so that weeks can be
// compared later.
type Week struct {
	// Start and End bound the period, from the last summary to this one.
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	// Days is the length of the period in days, DaysChecked the days a run
	// happened on.
	Days        int `json:"days"`
	DaysChecked int `json:"daysChecked"`
	// Reached is set when a run of the period reached at least one service.
	// Without it the other numbers describe an older run, or nothing.
	Reached bool `json:"reached"`
	// Compared is set when Fixed and New were counted, against a run before
	// the period.
	Compared bool `json:"compared"`
	Fixed    int  `json:"fixed"`
	New      int  `json:"new"`
	// FixDays are the days each fixed item had been open, from the run that
	// first found it to the run that found it fixed.
	FixDays []int `json:"fixDays,omitempty"`
	// Open counts the open items at the end of the period, by severity.
	Open     int `json:"open"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	// CatalogRead is set when the catalog of exploited flaws could be read.
	// Listed counts the flaws newly listed as exploited during the period
	// that were checked against the inventory, Affected those found in the
	// organisation's software, and Unchecked those listed after the last run
	// that reached something.
	CatalogRead bool `json:"catalogRead"`
	Listed      int  `json:"listed"`
	Affected    int  `json:"affected"`
	Unchecked   int  `json:"unchecked"`
}

type weeklyRecord struct {
	Sent  time.Time `json:"sent"`
	Weeks []Week    `json:"weeks,omitempty"`
}

func (s Store) weekly() (weeklyRecord, error) {
	var r weeklyRecord
	if err := readJSON(filepath.Join(s.Dir, weeklyFile), &r); err != nil && !errors.Is(err, os.ErrNotExist) {
		return weeklyRecord{}, err
	}
	return r, nil
}

// WeeklySent returns when the last weekly summary was sent, or the zero time
// if none was.
func (s Store) WeeklySent() (time.Time, error) {
	r, err := s.weekly()
	return r.Sent, err
}

// SaveWeeklySent records when the weekly summary was sent, without numbers:
// the first run records the day it starts counting from.
func (s Store) SaveWeeklySent(t time.Time) error {
	r, err := s.weekly()
	if err != nil {
		return err
	}
	r.Sent = t.UTC()
	return WriteJSON(filepath.Join(s.Dir, weeklyFile), r)
}

// SaveWeek records a weekly summary sent at t and its numbers, keeping the
// last MaxWeeks.
func (s Store) SaveWeek(w Week, t time.Time) error {
	r, err := s.weekly()
	if err != nil {
		return err
	}
	w.Start, w.End = w.Start.UTC(), w.End.UTC()
	r.Sent = t.UTC()
	r.Weeks = append(r.Weeks, w)
	if n := len(r.Weeks) - MaxWeeks; n > 0 {
		r.Weeks = r.Weeks[n:]
	}
	return WriteJSON(filepath.Join(s.Dir, weeklyFile), r)
}

// Weeks returns the numbers of the weekly summaries sent, oldest first.
func (s Store) Weeks() ([]Week, error) {
	r, err := s.weekly()
	return r.Weeks, err
}
