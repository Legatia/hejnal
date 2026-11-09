package deps

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestScanDir(t *testing.T) {
	pkgs, problems, err := ScanDir(context.Background(), "testdata/project")
	if err != nil || len(problems) != 0 {
		t.Fatalf("%v %v", problems, err)
	}
	var got []string
	for _, p := range pkgs {
		s := fmt.Sprintf("%s %s %s %s", p.File, p.Ecosystem, p.Name, p.Version)
		if p.Dev {
			s += " dev"
		}
		got = append(got, s)
	}
	sort.Strings(got)
	want := []string{
		"api/poetry.lock PyPI jinja2 2.11.2",
		"api/poetry.lock PyPI pytest 6.0.0 dev",
		"api/requirements.txt PyPI django 3.2.0",
		"api/requirements.txt PyPI pyyaml 5.3.1",
		"api/requirements.txt PyPI requests 2.25.1",
		"svc/Cargo.lock crates.io smallvec 1.6.0",
		"svc/Gemfile.lock RubyGems nokogiri 1.15.4",
		"svc/Gemfile.lock RubyGems rails 6.1.0",
		"svc/composer.lock Packagist guzzlehttp/guzzle 7.4.0",
		"svc/composer.lock Packagist phpunit/phpunit 9.5.0 dev",
		"svc/go.mod Go github.com/gin-gonic/gin 1.9.0",
		"svc/go.mod Go github.com/sirupsen/logrus 1.9.0",
		"svc/go.mod Go golang.org/x/net 0.17.0",
		"svc/gradle.lockfile Maven junit:junit 4.12 dev",
		"svc/gradle.lockfile Maven org.apache.logging.log4j:log4j-core 2.14.1",
		"svc/packages.lock.json NuGet Newtonsoft.Json 12.0.1",
		"svc/pom.xml Maven junit:junit 4.13 dev",
		"svc/pom.xml Maven org.springframework:spring-core 5.3.0",
		"web/package-lock.json npm jest 29.7.0 dev",
		"web/package-lock.json npm left-pad 1.3.0",
		"web/package-lock.json npm lodash 4.17.20",
		"web/package-lock.json npm minimist 1.2.5",
		"web/pnpm-lock.yaml npm @types/node 20.1.0",
		"web/pnpm-lock.yaml npm axios 1.6.0",
		"web/pnpm-lock.yaml npm react-dom 18.2.0",
		"web/yarn.lock npm @babel/core 7.1.2",
		"web/yarn.lock npm debug 4.1.1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, p := range pkgs {
		if p.File == "web/yarn.lock" && p.Name == "debug" && p.Line != 11 {
			t.Errorf("yarn line = %d", p.Line)
		}
	}
}

func TestOlderFormats(t *testing.T) {
	v1 := `{"lockfileVersion":1,"dependencies":{"express":{"version":"4.17.1","dependencies":{"qs":{"version":"6.7.0"}}},"mocha":{"version":"8.0.0","dev":true}}}`
	pkgs, err := Parse("package-lock.json", []byte(v1))
	if err != nil || len(pkgs) != 3 {
		t.Fatalf("v1: %+v %v", pkgs, err)
	}
	berry := "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\"web@workspace:.\":\n  version: 0.0.0-use.local\n"
	pkgs, _ = Parse("yarn.lock", []byte(berry))
	if len(pkgs) != 1 || pkgs[0].Name != "lodash" || pkgs[0].Version != "4.17.21" {
		t.Errorf("yarn berry: %+v", pkgs)
	}
	pnpm5 := "lockfileVersion: 5.4\n\npackages:\n\n  /@babel/core/7.1.0:\n    dev: true\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {}\n"
	pkgs, _ = Parse("pnpm-lock.yaml", []byte(pnpm5))
	if len(pkgs) != 2 || pkgs[0].Name != "@babel/core" || !pkgs[0].Dev || pkgs[1].Version != "18.2.0" {
		t.Errorf("pnpm 5: %+v", pkgs)
	}
	pip := `{"default":{"urllib3":{"version":"==1.26.4"}},"develop":{"black":{"version":"==22.1.0"}}}`
	pkgs, _ = Parse("Pipfile.lock", []byte(pip))
	if len(pkgs) != 2 || pkgs[0].Name != "black" || !pkgs[0].Dev {
		t.Errorf("Pipfile.lock: %+v", pkgs)
	}
}

func TestBadInput(t *testing.T) {
	for _, name := range []string{"package-lock.json", "composer.lock", "Pipfile.lock", "packages.lock.json"} {
		if _, err := Parse(name, []byte("{not json")); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Versions no advisory can match are left out.
	lock := `{"packages":{"node_modules/a":{"version":"file:../a"},"node_modules/b":{"version":"git+ssh://x"},"node_modules/c":{"version":"^1.0.0"},"node_modules/d":{"version":"1.0.0"}}}`
	pkgs, _ := Parse("package-lock.json", []byte(lock))
	if len(pkgs) != 1 || pkgs[0].Name != "d" {
		t.Errorf("odd versions: %+v", pkgs)
	}
	if Lockfile("README.md") || !Lockfile("requirements-dev.txt") || !Lockfile("x/Cargo.lock") {
		t.Error("Lockfile")
	}
	pkgs, _ = Parse("requirements-dev.txt", []byte("black==22.1.0\n"))
	if len(pkgs) != 1 || !pkgs[0].Dev {
		t.Errorf("dev requirements: %+v", pkgs)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("yarn.lock", "a@^1:\n  version \"1.0.0\"\n")
	f.Add("pnpm-lock.yaml", "packages:\n  /a/1.0.0:\n    dev: true\n")
	f.Add("Gemfile.lock", "GEM\n  specs:\n    a (1.0)\n")
	f.Add("pom.xml", "<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>")
	f.Add("poetry.lock", "[[package]]\nname = \"a\"\nversion = \"1\"\n")
	f.Fuzz(func(t *testing.T, name, data string) {
		pkgs, _ := Parse(name, []byte(data))
		for _, p := range pkgs {
			if !validName(p.Name) || !validVersion(p.Version) {
				t.Fatalf("invalid package %+v", p)
			}
		}
	})
}
