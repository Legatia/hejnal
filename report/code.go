package report

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/osv"
)

// Reports for what `hejnal code scan` finds: dependencies with advisories
// and settings in infrastructure code.

// depFixedIn returns the version that fixes every active advisory of a
// dependency item, the highest of their fixes, or "" if one has none.
func depFixedIn(g match.Group) string {
	best := ""
	for _, f := range match.Active(g.Findings) {
		if f.FixedIn == "" {
			return ""
		}
		if best == "" || osv.Compare(f.FixedIn, best) > 0 {
			best = f.FixedIn
		}
	}
	return best
}

// depStatus sums up a dependency item: malicious, exploited, likely to be,
// or none of these.
func depStatus(g match.Group) (malicious bool, exploited []match.Finding, epss float64) {
	for _, f := range match.Active(g.Findings) {
		malicious = malicious || f.Malicious
		if len(f.ListedBy) > 0 {
			exploited = append(exploited, f)
		}
		epss = max(epss, f.EPSS)
	}
	return
}

func depWhy(tr translator, g match.Group) string {
	active := match.Active(g.Findings)
	malicious, exploited, epss := depStatus(g)
	why := ""
	switch {
	case malicious:
		why = tr("dep.why.malicious")
	case len(exploited) > 0:
		why = tr("dep.why.kev", len(active), exploited[0].CVE, exploited[0].DateAdded)
	case epss >= 0.01:
		why = tr("dep.why.epss", len(active), fmt.Sprintf("%.0f%%", epss*100))
	default:
		why = tr("dep.why.quiet", len(active))
	}
	if g.Findings[0].Dev && !malicious {
		why += " " + tr("dep.why.dev")
	}
	return why
}

func depTodo(tr translator, g match.Group) string {
	malicious, _, _ := depStatus(g)
	switch {
	case malicious:
		return tr("dep.todo.malicious", g.Technology)
	case depFixedIn(g) != "":
		return tr("dep.todo", g.Technology, depFixedIn(g))
	}
	return tr("dep.todo.nofix", g.Technology)
}

// ecosystemLabel names an ecosystem for people.
func ecosystemLabel(e string) string {
	base, rel, _ := strings.Cut(e, ":")
	rel = strings.TrimSuffix(rel, ":LTS")
	switch base {
	case "Debian", "Ubuntu", "Alpine":
		return strings.TrimSpace(base + " " + strings.TrimPrefix(rel, "v"))
	case "crates.io":
		return "Rust"
	case "Packagist":
		return "PHP"
	case "RubyGems":
		return "Ruby"
	case "PyPI":
		return "Python"
	case "NuGet":
		return ".NET"
	}
	return base
}

func writeDependency(b *strings.Builder, tr translator, g match.Group, head func(string)) {
	head(groupTitle(tr, g))
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), depWhy(tr, g))
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), depTodo(tr, g))
	fmt.Fprintf(b, "- **%s:**\n", tr("label.advisories"))
	for i, f := range match.Active(g.Findings) {
		if i == maxFlaws {
			fmt.Fprintf(b, "  - %s\n", tr("sum.more", len(match.Active(g.Findings))-maxFlaws))
			break
		}
		parts := []string{mdCode(f.Advisory)}
		if f.CVE != "" && f.CVE != f.Advisory {
			parts = append(parts, mdCode(f.CVE))
		}
		if f.Name != "" {
			parts = append(parts, mdEscape(f.Name))
		}
		if len(f.ListedBy) > 0 {
			parts = append(parts, "**"+tr("dep.exploited")+"**")
		} else if f.EPSS >= 0.01 {
			parts = append(parts, tr("dep.epss", fmt.Sprintf("%.0f%%", f.EPSS*100)))
		}
		if f.FixedIn != "" {
			parts = append(parts, tr("dep.fixedin", mdCode(f.FixedIn)))
		}
		fmt.Fprintf(b, "  - %s\n", strings.Join(parts, " · "))
	}
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.found"), mdEscape(strings.Join(depPlaces(g), ", ")))
	proofLines(b, tr, g)
	b.WriteString("\n")
}

// depPlaces lists where a dependency was found.
func depPlaces(g match.Group) []string {
	var out []string
	for _, f := range g.Findings {
		p := f.File
		if f.Line > 0 {
			p = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
		if len(out) == 5 {
			break
		}
	}
	return out
}

func writeMisconfig(b *strings.Builder, tr translator, g match.Group, head func(string)) {
	f := g.Findings[0]
	head(itemTitle(tr, g))
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.why"), tr("misconfig.why."+f.TechID))
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.todo"), tr("misconfig.todo."+f.TechID))
	if len(g.Findings) == 1 {
		fmt.Fprintf(b, "- **%s:** %s · %s\n", tr("label.seen"), mdCode(codePlace(f)), mdEscape(f.Evidence))
	} else {
		fmt.Fprintf(b, "- **%s:**\n", tr("label.seen"))
		for _, x := range g.Findings {
			fmt.Fprintf(b, "  - %s · %s\n", mdCode(codePlace(x)), mdEscape(x.Evidence))
		}
	}
	proofLines(b, tr, g)
	b.WriteString("\n")
}

func codePlace(f match.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// safeArg matches a package name that can go in a command as it is.
var safeArg = regexp.MustCompile(`^[A-Za-z0-9@/._:+-]{1,200}$`)

// depCommand returns the command that shows which version is installed,
// and what pulls it in.
func depCommand(f match.Finding) string {
	name := f.Technology
	if f.Product != "" {
		name = f.Product // the installed binary package
	}
	if !safeArg.MatchString(name) || strings.HasPrefix(name, "-") {
		return ""
	}
	base, _, _ := strings.Cut(f.Ecosystem, ":")
	switch base {
	case "npm":
		return "npm ls " + name
	case "PyPI":
		return "pip show " + name
	case "Go":
		if name == "stdlib" {
			return "go version"
		}
		return "go list -m " + name
	case "crates.io":
		return "cargo tree -i " + name
	case "RubyGems":
		return "bundle info " + name
	case "Packagist":
		return "composer show " + name
	case "Maven":
		return "mvn dependency:tree -Dincludes=" + name
	case "NuGet":
		return "dotnet list package --include-transitive"
	case "Debian", "Ubuntu":
		return "dpkg -s " + name
	case "Alpine":
		return "apk info -v " + name
	}
	return ""
}

// depProof says how Hejnal knows a dependency item is real.
func depProof(tr translator, g match.Group, step func(bool, string, ...any)) (verdict, see, cmd string) {
	f := g.Findings[0]
	step(true, "proof.dep.installed", codePlace(f), g.Technology, g.Version)
	ids := []string{}
	for _, x := range match.Active(g.Findings) {
		ids = append(ids, x.Advisory)
	}
	step(true, "proof.dep.advisory", strings.Join(firstN(ids, 3), ", "), g.Version)
	malicious, exploited, epss := depStatus(g)
	verdict = VerdictConfirmed
	switch {
	case malicious:
		step(true, "proof.dep.malicious")
	case len(exploited) > 0:
		step(true, "proof.exploited.cisa", exploited[0].DateAdded)
	case epss >= 0.01:
		step(false, "proof.dep.epss", fmt.Sprintf("%.0f%%", epss*100))
	default:
		step(false, "proof.dep.notexploited")
	}
	if !malicious {
		// Whether the project calls the flawed code is not something a
		// lockfile shows.
		step(false, "proof.dep.reach")
	}
	if f.Dev && !malicious {
		step(false, "proof.dep.dev")
	}
	return verdict, tr("proof.see.dep", "https://osv.dev/vulnerability/"+f.Advisory), depCommand(f)
}
