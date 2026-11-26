package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/state"
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
	// Each summary's numbers are kept.
	if weeks, err := (state.Store{Dir: h.state}).Weeks(); err != nil || len(weeks) != 2 || weeks[1].Days != 7 || weeks[1].DaysChecked != 2 {
		t.Errorf("kept weeks = %+v, %v", weeks, err)
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
