package report

import (
	"slices"
	"testing"
	"time"
)

func TestParseWeekday(t *testing.T) {
	if d, on, err := ParseWeekday("Monday"); err != nil || !on || d != time.Monday {
		t.Errorf("Monday = %v %v %v", d, on, err)
	}
	if _, on, err := ParseWeekday("off"); err != nil || on {
		t.Errorf("off = %v %v", on, err)
	}
	if _, _, err := ParseWeekday("mon"); err == nil {
		t.Error("an abbreviated day was accepted")
	}
}

func TestWeeklyDue(t *testing.T) {
	mon := time.Date(2026, 11, 23, 7, 17, 0, 0, time.UTC) // a Monday
	for _, c := range []struct {
		last time.Time
		now  time.Time
		want bool
	}{
		{time.Time{}, mon, false},                           // nothing recorded yet
		{mon.AddDate(0, 0, -7), mon, true},                  // a week ago
		{mon.AddDate(0, 0, -2), mon, true},                  // recorded on Saturday, Hejnal's first run
		{mon.Add(-time.Hour), mon, false},                   // already sent this Monday
		{mon, mon.AddDate(0, 0, 1), false},                  // the day after it was sent
		{mon.AddDate(0, 0, -6), mon.AddDate(0, 0, 1), true}, // Monday was missed
		{mon.AddDate(0, 0, 1), mon.AddDate(0, 0, 6), false}, // sent late on Tuesday; wait for Monday
		{mon.AddDate(0, 0, 1), mon.AddDate(0, 0, 7), true},  // and send then
	} {
		if got := WeeklyDue(c.last, c.now, time.Monday); got != c.want {
			t.Errorf("WeeklyDue(%v, %v) = %v, want %v", c.last, c.now, got, c.want)
		}
	}
}

// TestWeeklyScheduleStaysOnTheDay runs the schedule over six weeks of daily
// runs that start on a Wednesday and miss one Monday and the Tuesday after.
func TestWeeklyScheduleStaysOnTheDay(t *testing.T) {
	var last time.Time
	var sent []string
	start := time.Date(2026, 11, 4, 7, 0, 0, 0, time.UTC) // a Wednesday
	for d := 0; d < 42; d++ {
		now := start.AddDate(0, 0, d)
		if day := now.Format(time.DateOnly); day == "2026-11-23" || day == "2026-11-24" {
			continue // the machine was off
		}
		switch {
		case last.IsZero():
			last = now
		case WeeklyDue(last, now, time.Monday):
			sent = append(sent, now.Format("Mon 01-02"))
			last = now
		}
	}
	want := []string{"Mon 11-09", "Mon 11-16", "Wed 11-25", "Mon 11-30", "Mon 12-07", "Mon 12-14"}
	if !slices.Equal(sent, want) {
		t.Errorf("sent on %v, want %v", sent, want)
	}
}
