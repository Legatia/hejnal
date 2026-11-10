package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Legatia/hejnal/match"
)

// Effort is a rough estimate of the work to fix an item, in minutes, for
// someone who knows the system: what deciding where to start needs, not a
// promise.
func Effort(g match.Group) int {
	switch g.Kind {
	case match.KindKEV:
		switch g.Category {
		case "edge", "remote-access", "network", "camera":
			// Appliance firmware: a maintenance window and a reboot.
			return 240
		}
		return 120
	case match.KindAdminExposed:
		return 30
	case match.KindTLSExpired, match.KindTLSExpiring, match.KindTakeover:
		return 15
	case match.KindExposedFile:
		switch g.TechID {
		case "env", "git", "script-secret":
			// Removing it is quick; replacing the keys it gave away is not.
			return 60
		case "non-production":
			return 30
		}
		return 15
	case match.KindEmail:
		if strings.HasPrefix(g.TechID, "spf") {
			return 30
		}
		return 15
	case match.KindSecret, match.KindBreach:
		return 60
	case match.KindDependency:
		if malicious, _, _ := depStatus(g); malicious {
			// Remove it, and replace every secret on machines that ran it.
			return 240
		}
		if depFixedIn(g) == "" {
			return 120
		}
		return 30
	case match.KindMisconfig:
		return 30
	}
	return 60
}

// QuickWin is the most effort an item may take to count as a quick win.
const QuickWin = 30

// FixOrder picks where to start: every critical and high item, most
// urgent first, and then quick wins, the medium and low items that take
// QuickWin minutes or less, quickest first.
func FixOrder(groups []match.Group) (first, quick []match.Group) {
	for _, g := range groups {
		switch {
		case g.Severity == match.Critical || g.Severity == match.High:
			first = append(first, g)
		case Effort(g) <= QuickWin:
			quick = append(quick, g)
		}
	}
	sort.SliceStable(first, func(i, j int) bool { return first[i].Score > first[j].Score })
	sort.SliceStable(quick, func(i, j int) bool {
		if ei, ej := Effort(quick[i]), Effort(quick[j]); ei != ej {
			return ei < ej
		}
		return quick[i].Score > quick[j].Score
	})
	return first, quick
}

// EffortText says an effort in words.
func EffortText(minutes int, lang string) string {
	return effortText(newTranslator(lang), minutes)
}

func effortText(tr translator, minutes int) string {
	switch {
	case minutes <= 15:
		return tr("effort.15")
	case minutes <= 30:
		return tr("effort.30")
	case minutes <= 60:
		return tr("effort.60")
	case minutes <= 120:
		return tr("effort.120")
	case minutes <= 240:
		return tr("effort.240")
	}
	return tr("effort.hours", (minutes+59)/60)
}

// maxStart is how many items "where to start" lists of each kind.
const maxStart = 5

// writeStart writes where to start: the urgent items and the quick wins,
// with rough effort, before the full list.
func writeStart(b *strings.Builder, tr translator, groups []match.Group, ids map[string]int) {
	first, quick := FixOrder(groups)
	if len(first)+len(quick) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", tr("start.title"))
	line := func(g match.Group) {
		ref := ""
		if n := ids[g.Key]; n > 0 {
			ref = fmt.Sprintf("%d. ", n)
		}
		fmt.Fprintf(b, "- %s%s · %s\n", ref, mdEscape(groupTitle(tr, g)), effortText(tr, Effort(g)))
	}
	total := 0
	if len(first) > 0 {
		fmt.Fprintf(b, "**%s**\n\n", tr("start.urgent"))
		for i, g := range first {
			total += Effort(g)
			if i < maxStart {
				line(g)
			}
		}
		if len(first) > maxStart {
			fmt.Fprintf(b, "- %s\n", tr("sum.more", len(first)-maxStart))
		}
		fmt.Fprintf(b, "\n%s\n\n", tr("start.total", effortText(tr, total)))
	}
	if len(quick) > 0 {
		fmt.Fprintf(b, "**%s**\n\n", tr("start.quick"))
		for i, g := range quick {
			if i == maxStart {
				fmt.Fprintf(b, "- %s\n", tr("sum.more", len(quick)-maxStart))
				break
			}
			line(g)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "%s\n\n", tr("start.note"))
}
