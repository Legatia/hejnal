package report

import (
	"errors"
	"strings"
	"time"
)

// ParseWeekday reads the day the weekly summary goes out: a day of the week
// in English, such as "monday", or "off". ok is false for off.
func ParseWeekday(s string) (day time.Weekday, ok bool, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "off" || s == "none" {
		return 0, false, nil
	}
	for d := time.Sunday; d <= time.Saturday; d++ {
		if s == strings.ToLower(d.String()) {
			return d, true, nil
		}
	}
	return 0, false, errors.New("must be a day of the week, such as monday, or off")
}

// WeeklyDue reports whether the weekly summary is due: when none was sent
// since the start of the last chosen day, in now's time zone. A run on that
// day sends it; if no run happened that day, the next run does, and the one
// after that waits for the chosen day again. The zero last means nothing is
// recorded yet, and then it is not due.
func WeeklyDue(last, now time.Time, day time.Weekday) bool {
	if last.IsZero() {
		return false
	}
	y, mo, d := now.Date()
	back := (int(now.Weekday()) - int(day) + 7) % 7
	anchor := time.Date(y, mo, d-back, 0, 0, 0, 0, now.Location())
	return last.Before(anchor)
}
