package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseWeekday(t *testing.T) {
	if d, on, err := parseWeekday("Monday"); err != nil || !on || d != time.Monday {
		t.Errorf("Monday = %v %v %v", d, on, err)
	}
	if _, on, err := parseWeekday("off"); err != nil || on {
		t.Errorf("off = %v %v", on, err)
	}
	if _, _, err := parseWeekday("mon"); err == nil {
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
		if got := weeklyDue(c.last, c.now, time.Monday); got != c.want {
			t.Errorf("weeklyDue(%v, %v) = %v, want %v", c.last, c.now, got, c.want)
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
		case weeklyDue(last, now, time.Monday):
			sent = append(sent, now.Format("Mon 01-02"))
			last = now
		}
	}
	want := []string{"Mon 11-09", "Mon 11-16", "Wed 11-25", "Mon 11-30", "Mon 12-07", "Mon 12-14"}
	if !slices.Equal(sent, want) {
		t.Errorf("sent on %v, want %v", sent, want)
	}
}

func TestRunSendsWeeklySummary(t *testing.T) {
	h := newHarness(t)
	h.now = time.Date(2026, 11, 4, 7, 0, 0, 0, time.UTC) // a Wednesday
	if code, out, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("first run exit %d\n%s\n%s", code, out, errOut)
	}
	if len(h.messages) != 1 {
		t.Fatalf("first run messages = %q", h.messages)
	}

	// PHP no longer shows its name, as behind a maintenance page or a proxy
	// that strips the header. That does not prove it is fixed, so nobody
	// is told it is.
	h.setPHP("-")
	h.now = time.Date(2026, 11, 6, 7, 0, 0, 0, time.UTC)
	code, out, errOut := h.run(h.runArgs()...)
	if code != exitOK {
		t.Fatalf("second run exit %d\n%s\n%s", code, out, errOut)
	}
	for _, m := range h.messages {
		if strings.Contains(m, "Fixed") {
			t.Fatalf("a product that stopped showing was announced as fixed: %q", m)
		}
	}
	sent := len(h.messages)

	// The first Monday the summary goes out though nothing is new. It covers
	// the days since the first run.
	h.now = time.Date(2026, 11, 9, 7, 0, 0, 0, time.UTC)
	if code, out, errOut = h.run(h.runArgs()...); code != exitOK || len(h.messages) != sent+1 {
		t.Fatalf("third run exit %d, messages %q\n%s\n%s", code, h.messages, out, errOut)
	}
	weekly := h.messages[sent]
	for _, want := range []string{"week of 2026-11-04 to 2026-11-09", "Checked on 2 of the last 5 days", "Fixed this week: 0", "Open: 1"} {
		if !strings.Contains(weekly, want) {
			t.Errorf("weekly summary is missing %q:\n%s", want, weekly)
		}
	}
	if !strings.Contains(out, "Weekly summary sent.") {
		t.Errorf("run does not say it sent the summary:\n%s", out)
	}
	// Not again on Tuesday.
	h.now = time.Date(2026, 11, 10, 7, 0, 0, 0, time.UTC)
	if code, _, _ = h.run(h.runArgs()...); code != exitOK || len(h.messages) != sent+1 {
		t.Errorf("summary sent twice in a week: %d messages", len(h.messages))
	}
	// The next Monday it follows on from the last one.
	h.now = time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC)
	if code, _, errOut = h.run(h.runArgs()...); code != exitOK || len(h.messages) != sent+2 {
		t.Fatalf("fourth run exit %d, %d messages\n%s", code, len(h.messages), errOut)
	}
	if weekly = h.messages[sent+1]; !strings.Contains(weekly, "week of 2026-11-09 to 2026-11-16") || !strings.Contains(weekly, "Checked on 2 of the last 7 days") {
		t.Errorf("second weekly summary:\n%s", weekly)
	}
	// -weekly off turns it off.
	h.now = time.Date(2026, 11, 30, 7, 0, 0, 0, time.UTC)
	if code, _, _ = h.run(h.runArgs("-weekly", "off")...); code != exitOK || len(h.messages) != sent+2 {
		t.Errorf("summary sent with -weekly off: %d messages", len(h.messages))
	}
	code, out, _ = h.run("report", "weekly", "-state", h.state)
	if code != exitOK || !strings.Contains(out, "week of") {
		t.Errorf("report weekly (exit %d):\n%s", code, out)
	}
}
