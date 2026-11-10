// Package deps finds the third-party packages a project or a container image
// installs, from the lockfiles and package databases that record exact
// versions: npm, Yarn and pnpm; pip, Pipenv, Poetry, uv and PDM; Go modules;
// Cargo; Bundler; Composer; Maven and Gradle; NuGet; and the Debian, Ubuntu
// and Alpine package databases.
//
// It reads files only. It never runs a package manager, installs anything or
// sends anything anywhere; matching the packages against advisories is the
// osv package's job. Names and ecosystems are those of OSV
// (https://ossf.github.io/osv-schema/), so the result can be matched as it is.
package deps

import (
	"cmp"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// OSV ecosystem names.
const (
	Npm       = "npm"
	PyPI      = "PyPI"
	Go        = "Go"
	Cargo     = "crates.io"
	RubyGems  = "RubyGems"
	Packagist = "Packagist"
	Maven     = "Maven"
	NuGet     = "NuGet"
)

// Package is one package at one version, as a lockfile or package database
// records it.
type Package struct {
	// Ecosystem is OSV's name for the package registry or distribution,
	// such as "npm" or "Debian:12".
	Ecosystem string `json:"ecosystem"`
	// Name is the name advisories use: for Debian, Ubuntu and Alpine, the
	// source package's.
	Name    string `json:"name"`
	Version string `json:"version"`
	// Binary is the installed package's own name, when advisories use its
	// source package's name instead.
	Binary string `json:"binary,omitempty"`
	// File is where the package was found, relative to the scanned root,
	// with forward slashes, and Line its line there when known.
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
	// Dev marks a package only development or tests use.
	Dev bool `json:"dev,omitempty"`
}

// MaxFileSize is the largest lockfile read: 64 MiB.
const MaxFileSize = 64 << 20

// parser reads one kind of file. name is the file's path for messages.
type parser func(name string, data []byte) ([]Package, error)

// parserFor returns the parser for a file name, or nil.
func parserFor(file string) parser {
	base := path.Base(file)
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parseNpmLock
	case "yarn.lock":
		return parseYarnLock
	case "pnpm-lock.yaml":
		return parsePnpmLock
	case "Pipfile.lock":
		return parsePipfileLock
	case "poetry.lock", "uv.lock", "pdm.lock":
		return parsePyTOMLLock
	case "go.mod":
		return parseGoMod
	case "Cargo.lock":
		return parseCargoLock
	case "Gemfile.lock", "gems.locked":
		return parseGemfileLock
	case "composer.lock":
		return parseComposerLock
	case "gradle.lockfile":
		return parseGradleLock
	case "pom.xml":
		return parsePom
	case "packages.lock.json":
		return parseNuGetLock
	}
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return parseRequirements
	}
	return nil
}

// Lockfile reports whether Parse can read a file with this name.
func Lockfile(name string) bool { return parserFor(name) != nil }

// Parse reads the packages in one lockfile; name decides the format and is
// what each Package's File says.
func Parse(name string, data []byte) ([]Package, error) {
	p := parserFor(name)
	if p == nil {
		return nil, nil
	}
	out, err := p(name, data)
	if err != nil {
		return nil, err
	}
	return clean(out), nil
}

// skipDirs are never entered: installed copies, caches and build output
// rather than what the project declares.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "bower_components": true, "vendor": true,
	".venv": true, "venv": true, ".tox": true, "__pycache__": true, ".terraform": true,
	".gradle": true, ".idea": true, "target": true,
}

// Problem is a lockfile that could not be read.
type Problem struct {
	File string `json:"file"`
	Err  string `json:"error"`
}

// ScanDir finds every lockfile under root and reads its packages. Files it
// cannot read are reported as problems, not errors, so one broken lockfile
// does not hide the others.
func ScanDir(ctx context.Context, root string) ([]Package, []Problem, error) {
	var out []Package
	var problems []Problem
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || parserFor(d.Name()) == nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		data, err := readLimited(p)
		if err != nil {
			problems = append(problems, Problem{File: rel, Err: err.Error()})
			return nil
		}
		pkgs, err := Parse(rel, data)
		if err != nil {
			problems = append(problems, Problem{File: rel, Err: err.Error()})
			return nil
		}
		out = append(out, pkgs...)
		return nil
	})
	return out, problems, err
}

func readLimited(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, errTooLarge
	}
	return data, nil
}

// clean drops packages without a usable name or version and repeats, and
// sorts the rest.
func clean(ps []Package) []Package {
	seen := map[string]bool{}
	out := ps[:0]
	for _, p := range ps {
		p.Name, p.Version = strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
		if !validName(p.Name) || !validVersion(p.Version) {
			continue
		}
		k := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version + "\x00" + p.File
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Package) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.Ecosystem, b.Ecosystem), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version))
	})
	return out
}

func validName(s string) bool {
	if s == "" || len(s) > 214+100 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// validVersion accepts versions a registry gives out, and refuses paths,
// URLs, Git references and ranges, which no advisory can be matched to.
// A "~" inside a version is allowed: Debian and Ubuntu use it for every
// security update (3.0.15-1~deb12u1). A range such as "~1.2" is still
// refused, because a version must start with a digit.
func validVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if strings.ContainsAny(s, " /\\<>=^*|") || strings.Contains(s, "://") {
		return false
	}
	for _, pre := range []string{"file:", "link:", "git", "http", "workspace:", "portal:", "patch:", "npm:", "github:", "dev-"} {
		if strings.HasPrefix(s, pre) {
			return false
		}
	}
	return s[0] >= '0' && s[0] <= '9' || s[0] == 'v' && len(s) > 1 && s[1] >= '0' && s[1] <= '9'
}
