package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var errTooLarge = errors.New("larger than 64 MiB")

// lines calls fn for each line with its 1-based number.
func lines(data []byte, fn func(n int, line string)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		fn(n, sc.Text())
	}
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// npm: package-lock.json and npm-shrinkwrap.json, all lockfile versions.
func parseNpmLock(name string, data []byte) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Dev      bool   `json:"dev"`
			Link     bool   `json:"link"`
			Resolved string `json:"resolved"`
		} `json:"packages"`
		Dependencies map[string]npmV1 `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("not a package-lock.json: %w", err)
	}
	var out []Package
	if len(lock.Packages) > 0 {
		for p, e := range lock.Packages {
			i := strings.LastIndex(p, "node_modules/")
			if i < 0 || e.Link {
				continue // the project itself, or a workspace link
			}
			n := p[i+len("node_modules/"):]
			if e.Name != "" {
				n = e.Name // installed under an alias
			}
			out = append(out, Package{Ecosystem: Npm, Name: n, Version: e.Version, File: name, Dev: e.Dev})
		}
		return out, nil
	}
	var walk func(map[string]npmV1, int)
	walk = func(m map[string]npmV1, depth int) {
		if depth > 64 {
			return
		}
		for n, e := range m {
			out = append(out, Package{Ecosystem: Npm, Name: n, Version: e.Version, File: name, Dev: e.Dev})
			walk(e.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return out, nil
}

type npmV1 struct {
	Version      string           `json:"version"`
	Dev          bool             `json:"dev"`
	Dependencies map[string]npmV1 `json:"dependencies"`
}

// npmName returns the package name in a specifier such as "@scope/x@^1".
func npmName(spec string) string {
	spec = unquote(spec)
	if i := strings.Index(spec[min(1, len(spec)):], "@"); i >= 0 {
		return spec[:i+1]
	}
	return spec
}

// yarn.lock, both Yarn 1 and Yarn 2+ formats.
func parseYarnLock(name string, data []byte) ([]Package, error) {
	var out []Package
	cur, curLine := "", 0
	lines(data, func(n int, line string) {
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") {
			first := strings.SplitN(strings.TrimSuffix(line, ":"), ",", 2)[0]
			cur, curLine = npmName(first), n
			if strings.Contains(first, "@workspace:") || strings.Contains(first, "@patch:") || cur == "__metadata" {
				cur = ""
			}
			return
		}
		t := strings.TrimSpace(line)
		if cur == "" || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "    ") {
			return
		}
		var v string
		switch {
		case strings.HasPrefix(t, "version: "):
			v = unquote(strings.TrimPrefix(t, "version: "))
		case strings.HasPrefix(t, "version "):
			v = unquote(strings.TrimPrefix(t, "version "))
		default:
			return
		}
		out = append(out, Package{Ecosystem: Npm, Name: cur, Version: v, File: name, Line: curLine})
		cur = ""
	})
	return out, nil
}

// pnpmKey matches a package key in pnpm-lock.yaml's packages section:
// "/name/1.2.3" (version 5), "/name@1.2.3" (6) or "name@1.2.3" (9), with
// peer-dependency suffixes.
var pnpmKey = regexp.MustCompile(`^/?((?:@[^/@]+/)?[^/@(]+)[/@]([0-9][^(_/]*)`)

func parsePnpmLock(name string, data []byte) ([]Package, error) {
	var out []Package
	section := ""
	last := -1
	lines(data, func(n int, line string) {
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			return
		}
		if line[0] != ' ' {
			section = strings.TrimSuffix(strings.TrimSpace(line), ":")
			last = -1
			return
		}
		if section != "packages" {
			return
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(line, ":") {
			key := unquote(strings.TrimSuffix(strings.TrimSpace(line), ":"))
			if m := pnpmKey.FindStringSubmatch(key); m != nil {
				out = append(out, Package{Ecosystem: Npm, Name: m[1], Version: m[2], File: name, Line: n})
				last = len(out) - 1
			}
			return
		}
		if last >= 0 && strings.TrimSpace(line) == "dev: true" {
			out[last].Dev = true
		}
	})
	return out, nil
}

// pyName normalises a Python package name as PEP 503 says, which is how
// OSV names PyPI packages.
var pySep = regexp.MustCompile(`[-_.]+`)

func pyName(s string) string {
	return pySep.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
}

var pinRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,\\]*)`)

// requirements*.txt: only pinned requirements (name==version) say what is
// installed.
func parseRequirements(name string, data []byte) ([]Package, error) {
	dev := strings.Contains(strings.ToLower(name), "dev") || strings.Contains(strings.ToLower(name), "test")
	var out []Package
	lines(data, func(n int, line string) {
		if m := pinRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			out = append(out, Package{Ecosystem: PyPI, Name: pyName(m[1]), Version: m[2], File: name, Line: n, Dev: dev})
		}
	})
	return out, nil
}

func parsePipfileLock(name string, data []byte) ([]Package, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("not a Pipfile.lock: %w", err)
	}
	var out []Package
	for _, sec := range []string{"default", "develop"} {
		var pkgs map[string]struct {
			Version string `json:"version"`
		}
		if raw, ok := lock[sec]; ok {
			if err := json.Unmarshal(raw, &pkgs); err != nil {
				return nil, fmt.Errorf("Pipfile.lock %s: %w", sec, err)
			}
		}
		for n, p := range pkgs {
			out = append(out, Package{Ecosystem: PyPI, Name: pyName(n), Version: strings.TrimPrefix(p.Version, "=="), File: name, Dev: sec == "develop"})
		}
	}
	return out, nil
}

// tomlPackages reads the [[package]] tables of a lockfile in TOML: each
// table's name, version and, if present, source, with the table's line.
func tomlPackages(data []byte) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	lines(data, func(n int, line string) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			cur = nil
			if t == "[[package]]" {
				cur = map[string]string{"#line": fmt.Sprint(n)}
				out = append(out, cur)
			}
			return
		}
		if cur == nil {
			return
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return
		}
		k = strings.TrimSpace(k)
		switch k {
		case "name", "version", "source", "category":
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "\"") {
				if end := strings.Index(v[1:], "\""); end >= 0 {
					v = v[1 : end+1]
				}
			} else if strings.HasPrefix(v, "{") {
				v = "table"
			}
			cur[k] = v
		}
	})
	return out
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// poetry.lock, uv.lock and pdm.lock.
func parsePyTOMLLock(name string, data []byte) ([]Package, error) {
	var out []Package
	for _, t := range tomlPackages(data) {
		// uv lists the project itself, from a local source.
		if strings.HasPrefix(t["source"], "table") && strings.HasSuffix(name, "uv.lock") && t["version"] == "" {
			continue
		}
		out = append(out, Package{Ecosystem: PyPI, Name: pyName(t["name"]), Version: t["version"], File: name, Line: atoi(t["#line"]), Dev: t["category"] == "dev"})
	}
	return out, nil
}

func parseCargoLock(name string, data []byte) ([]Package, error) {
	var out []Package
	for _, t := range tomlPackages(data) {
		if t["source"] == "" {
			continue // a crate of this workspace, not from a registry
		}
		out = append(out, Package{Ecosystem: Cargo, Name: t["name"], Version: t["version"], File: name, Line: atoi(t["#line"])})
	}
	return out, nil
}

// go.mod lists every module the build uses since Go 1.17.
func parseGoMod(name string, data []byte) ([]Package, error) {
	var out []Package
	block := false
	lines(data, func(n int, line string) {
		t := strings.TrimSpace(line)
		if i := strings.Index(t, "//"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		switch {
		case t == "require (":
			block = true
			return
		case block && t == ")":
			block = false
			return
		case strings.HasPrefix(t, "require ") && !strings.HasSuffix(t, "("):
			t = strings.TrimSpace(strings.TrimPrefix(t, "require "))
		case !block:
			return
		}
		f := strings.Fields(t)
		if len(f) >= 2 {
			out = append(out, Package{Ecosystem: Go, Name: unquote(f[0]), Version: strings.TrimPrefix(f[1], "v"), File: name, Line: n})
		}
	})
	return out, nil
}

var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9_.-]+) \(([0-9][^)]*)\)$`)

// rubyPlatform matches the platform suffix of a gem built for one platform.
var rubyPlatform = regexp.MustCompile(`-(x86|x64|x86_64|aarch64|arm64|arm|universal|java|mingw|mswin|i386|i686|ppc|powerpc|s390x)[A-Za-z0-9_-]*$`)

func parseGemfileLock(name string, data []byte) ([]Package, error) {
	var out []Package
	section, specs := "", false
	lines(data, func(n int, line string) {
		if line != "" && line[0] != ' ' {
			section, specs = strings.TrimSpace(line), false
			return
		}
		if strings.TrimSpace(line) == "specs:" {
			specs = true
			return
		}
		if section != "GEM" || !specs {
			return
		}
		if m := gemSpec.FindStringSubmatch(line); m != nil {
			out = append(out, Package{Ecosystem: RubyGems, Name: m[1], Version: rubyPlatform.ReplaceAllString(m[2], ""), File: name, Line: n})
		}
	})
	return out, nil
}

func parseComposerLock(name string, data []byte) ([]Package, error) {
	var lock struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("not a composer.lock: %w", err)
	}
	var out []Package
	for _, p := range lock.Packages {
		out = append(out, Package{Ecosystem: Packagist, Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), File: name})
	}
	for _, p := range lock.PackagesDev {
		out = append(out, Package{Ecosystem: Packagist, Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), File: name, Dev: true})
	}
	return out, nil
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// gradle.lockfile: group:artifact:version=configurations.
func parseGradleLock(name string, data []byte) ([]Package, error) {
	var out []Package
	lines(data, func(n int, line string) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "empty=") {
			return
		}
		coord, confs, _ := strings.Cut(t, "=")
		f := strings.Split(coord, ":")
		if len(f) != 3 {
			return
		}
		// Only tests use it if every configuration that resolved it is a
		// test one.
		dev := confs != ""
		for _, c := range strings.Split(confs, ",") {
			dev = dev && strings.Contains(strings.ToLower(c), "test")
		}
		out = append(out, Package{Ecosystem: Maven, Name: f[0] + ":" + f[1], Version: f[2], File: name, Line: n, Dev: dev})
	})
	return out, nil
}

// pom.xml: dependencies with a literal version, or one from the POM's own
// properties. Versions a parent POM or a BOM decides are not known here.
func parsePom(name string, data []byte) ([]Package, error) {
	var pom struct {
		Properties struct {
			Any []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"properties"`
		Version string `xml:"version"`
		Deps    []struct {
			Group    string `xml:"groupId"`
			Artifact string `xml:"artifactId"`
			Version  string `xml:"version"`
			Scope    string `xml:"scope"`
		} `xml:"dependencies>dependency"`
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	if err := d.Decode(&pom); err != nil {
		return nil, fmt.Errorf("not a pom.xml: %w", err)
	}
	props := map[string]string{"project.version": strings.TrimSpace(pom.Version)}
	for _, p := range pom.Properties.Any {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}
	var out []Package
	for _, dep := range pom.Deps {
		v := strings.TrimSpace(dep.Version)
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			v = props[v[2:len(v)-1]]
		}
		if dep.Group == "" || dep.Artifact == "" || v == "" || strings.ContainsAny(v, "[]()${},") {
			continue
		}
		scope := strings.TrimSpace(dep.Scope)
		out = append(out, Package{Ecosystem: Maven, Name: strings.TrimSpace(dep.Group) + ":" + strings.TrimSpace(dep.Artifact), Version: v, File: name, Dev: scope == "test" || scope == "provided"})
	}
	return out, nil
}

// packages.lock.json of NuGet.
func parseNuGetLock(name string, data []byte) ([]Package, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
			Type     string `json:"type"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("not a packages.lock.json: %w", err)
	}
	var out []Package
	for _, pkgs := range lock.Dependencies {
		for n, p := range pkgs {
			if p.Type == "Project" {
				continue
			}
			out = append(out, Package{Ecosystem: NuGet, Name: n, Version: p.Resolved, File: name})
		}
	}
	return out, nil
}
