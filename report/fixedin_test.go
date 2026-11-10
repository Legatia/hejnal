package report

import (
	"testing"

	"github.com/Legatia/hejnal/match"
)

func TestDepFixedInPicksTheHighestFix(t *testing.T) {
	for _, c := range []struct {
		fixes []string
		want  string
	}{
		{[]string{"1.2.3-rc1", "1.2.3"}, "1.2.3"},
		{[]string{"1.2.3", "1.2.3-rc1"}, "1.2.3"},
		{[]string{"4.17.21", "4.17.12", "4.17.19"}, "4.17.21"},
		{[]string{"3.0.11-1~deb12u2", "3.0.13-1~deb12u1"}, "3.0.13-1~deb12u1"},
		{[]string{"2.15.0", ""}, ""},
	} {
		var g match.Group
		for _, v := range c.fixes {
			g.Findings = append(g.Findings, match.Finding{FixedIn: v})
		}
		if got := depFixedIn(g); got != c.want {
			t.Errorf("depFixedIn(%q) = %q, want %q", c.fixes, got, c.want)
		}
	}
}
