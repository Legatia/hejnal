package main

import (
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
		{time.Time{}, mon, false},           // nothing recorded yet
		{mon.AddDate(0, 0, -7), mon, true},  // a week ago
		{mon.AddDate(0, 0, -2), mon, false}, // recorded on Saturday
		{mon.Add(-6*24*time.Hour + time.Minute), mon, false},
		{mon.AddDate(0, 0, -9), mon.AddDate(0, 0, 1), true}, // Monday was missed
		{mon, mon.AddDate(0, 0, 1), false},                  // the day after it was sent
	} {
		if got := weeklyDue(c.last, c.now, time.Monday); got != c.want {
			t.Errorf("weeklyDue(%v, %v) = %v, want %v", c.last, c.now, got, c.want)
		}
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

	// Nothing new on Monday, five days after the first run: no summary yet.
	h.now = time.Date(2026, 11, 9, 7, 0, 0, 0, time.UTC)
	if code, _, errOut = h.run(h.runArgs()...); code != exitOK || len(h.messages) != sent {
		t.Fatalf("third run exit %d, %d messages\n%s", code, len(h.messages), errOut)
	}

	// The next Monday the summary goes out though nothing is new.
	h.now = time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC)
	if code, out, errOut = h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("fourth run exit %d\n%s\n%s", code, out, errOut)
	}
	if len(h.messages) != sent+1 {
		t.Fatalf("weekly summary not sent: %q", h.messages)
	}
	weekly := h.messages[sent]
	for _, want := range []string{"week of 2026-11-09 to 2026-11-16", "Checked on 1 of the last 7 days", "Fixed this week: 0", "Open: 1"} {
		if !strings.Contains(weekly, want) {
			t.Errorf("weekly summary is missing %q:\n%s", want, weekly)
		}
	}
	if !strings.Contains(out, "Weekly summary sent.") {
		t.Errorf("run does not say it sent the summary:\n%s", out)
	}
	// Once a week only.
	h.now = h.now.Add(24 * time.Hour)
	if code, _, _ = h.run(h.runArgs()...); code != exitOK || len(h.messages) != sent+1 {
		t.Errorf("summary sent twice in a week: %d messages", len(h.messages))
	}
	// -weekly off turns it off.
	h.now = time.Date(2026, 11, 30, 7, 0, 0, 0, time.UTC)
	if code, _, _ = h.run(h.runArgs("-weekly", "off")...); code != exitOK || len(h.messages) != sent+1 {
		t.Errorf("summary sent with -weekly off: %d messages", len(h.messages))
	}
	code, out, _ = h.run("report", "weekly", "-state", h.state)
	if code != exitOK || !strings.Contains(out, "week of") {
		t.Errorf("report weekly (exit %d):\n%s", code, out)
	}
}
