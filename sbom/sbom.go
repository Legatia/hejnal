// Package sbom writes the packages a code scan found as a software bill of
// materials in CycloneDX 1.6 JSON (https://cyclonedx.org), the format
// Dependency-Track and other tools import.
//
// The list holds what lockfiles and package databases record: each package
// once, with its version, its package URL and the files that name it. It
// has no dependency graph, licences or hashes, because those files do not
// say them all, and no advisories: those change daily, and the fix list and
// SARIF carry them.
package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/Legatia/hejnal/deps"
)

// Options describe the document around the list of packages.
type Options struct {
	// Project names what the packages belong to.
	Project string
	// Time is when the packages were read.
	Time time.Time
	// ToolVersion is Hejnal's version.
	ToolVersion string
	// Serial is the document's serial number, "urn:uuid:" and a UUID. Left
	// empty, each document gets a random one.
	Serial string
}

type occurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

type evidence struct {
	Occurrences []occurrence `json:"occurrences"`
}

type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type component struct {
	Type               string      `json:"type"`
	BOMRef             string      `json:"bom-ref,omitempty"`
	Group              string      `json:"group,omitempty"`
	Name               string      `json:"name"`
	Version            string      `json:"version,omitempty"`
	Scope              string      `json:"scope,omitempty"`
	PURL               string      `json:"purl,omitempty"`
	ExternalReferences []reference `json:"externalReferences,omitempty"`
	Evidence           *evidence   `json:"evidence,omitempty"`
}

type tools struct {
	Components []component `json:"components"`
}

type metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     tools     `json:"tools"`
	Component component `json:"component"`
}

type document struct {
	Format       string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

// CycloneDX writes the packages as a CycloneDX 1.6 document, and returns
// how many components it lists. A package found in several files is one
// component with each place as an occurrence. A package only development
// or tests use, wherever it was found, has the scope "excluded", CycloneDX's
// word for one that does not run with the product.
func CycloneDX(w io.Writer, pkgs []deps.Package, o Options) (int, error) {
	serial := o.Serial
	if serial == "" {
		var err error
		if serial, err = newSerial(); err != nil {
			return 0, err
		}
	}
	type entry struct {
		component
		dev bool
	}
	byRef := map[string]*entry{}
	var refs []string
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		id := PURL(p)
		e := byRef[id]
		if e == nil {
			group, name := names(p)
			e = &entry{component: component{Type: "library", BOMRef: id, Group: group, Name: name, Version: p.Version, PURL: id, Evidence: &evidence{}}, dev: true}
			byRef[id] = e
			refs = append(refs, id)
		}
		e.dev = e.dev && p.Dev
		if p.File != "" {
			if oc := (occurrence{Location: p.File, Line: max(p.Line, 0)}); !slices.Contains(e.Evidence.Occurrences, oc) {
				e.Evidence.Occurrences = append(e.Evidence.Occurrences, oc)
			}
		}
	}
	slices.Sort(refs)
	doc := document{
		Format:       "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: serial,
		Version:      1,
		Metadata: metadata{
			Timestamp: o.Time.UTC().Format(time.RFC3339),
			Tools: tools{Components: []component{{
				Type: "application", Name: "hejnal", Version: o.ToolVersion,
				ExternalReferences: []reference{{Type: "website", URL: "https://github.com/Legatia/hejnal"}},
			}}},
			Component: component{Type: "application", Name: o.Project},
		},
		Components: []component{},
	}
	for _, id := range refs {
		e := byRef[id]
		if e.dev {
			e.Scope = "excluded"
		}
		if len(e.Evidence.Occurrences) == 0 {
			e.Evidence = nil
		} else {
			slices.SortFunc(e.Evidence.Occurrences, func(a, b occurrence) int {
				if c := strings.Compare(a.Location, b.Location); c != 0 {
					return c
				}
				return a.Line - b.Line
			})
		}
		doc.Components = append(doc.Components, e.component)
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return len(doc.Components), enc.Encode(doc)
}

// newSerial returns "urn:uuid:" and a random (version 4) UUID.
func newSerial() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// names returns the component's group and name, split the way each
// registry's own CycloneDX tools split them: an npm scope, a Maven group
// ID and a Composer vendor are groups. A distribution's package goes by
// the name it is installed under.
func names(p deps.Package) (group, name string) {
	eco, _, _ := strings.Cut(p.Ecosystem, ":")
	switch eco {
	case deps.Npm:
		if scope, rest, ok := strings.Cut(p.Name, "/"); ok && strings.HasPrefix(scope, "@") {
			return scope, rest
		}
	case deps.Maven:
		if g, a, ok := strings.Cut(p.Name, ":"); ok {
			return g, a
		}
	case deps.Packagist:
		if vendor, rest, ok := strings.Cut(p.Name, "/"); ok {
			return vendor, rest
		}
	case "Debian", "Ubuntu", "Alpine":
		if p.Binary != "" {
			return "", p.Binary
		}
	}
	return "", p.Name
}

// PURL returns the package's package URL
// (https://github.com/package-url/purl-spec), the identifier tools match
// components by, such as "pkg:npm/%40babel/core@7.24.0" or
// "pkg:deb/debian/libssl3@3.0.9-1?distro=debian-12&upstream=openssl".
func PURL(p deps.Package) string {
	eco, release, _ := strings.Cut(p.Ecosystem, ":")
	typ, name, version := "generic", p.Name, p.Version
	var namespace []string
	var qualifiers []string
	split := func(sep string) {
		if i := strings.LastIndex(name, sep); i >= 0 {
			namespace, name = strings.Split(name[:i], "/"), name[i+len(sep):]
		}
	}
	distro := func(family string) {
		if p.Binary != "" {
			name = p.Binary
		}
		name = strings.ToLower(name)
		namespace = []string{family}
		// OSV writes "Ubuntu:22.04:LTS" and "Alpine:v3.19".
		release, _, _ = strings.Cut(release, ":")
		if release = strings.TrimPrefix(release, "v"); release != "" {
			qualifiers = append(qualifiers, "distro="+escape(family+"-"+release))
		}
		if p.Binary != "" && p.Name != "" && !strings.EqualFold(p.Binary, p.Name) {
			qualifiers = append(qualifiers, "upstream="+escape(p.Name))
		}
	}
	switch eco {
	case deps.Npm:
		typ = "npm"
		split("/")
	case deps.PyPI:
		typ, name = "pypi", strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case deps.Go:
		typ, name = "golang", strings.ToLower(name)
		split("/")
		// Lockfiles write module versions as v1.2.3; the Go release a
		// program was built with has no "v".
		if p.Name != "stdlib" && version != "" && version[0] >= '0' && version[0] <= '9' {
			version = "v" + version
		}
	case deps.Cargo:
		typ = "cargo"
	case deps.RubyGems:
		typ = "gem"
	case deps.Packagist:
		typ, name = "composer", strings.ToLower(name)
		split("/")
	case deps.Maven:
		typ = "maven"
		split(":")
	case deps.NuGet:
		typ = "nuget"
	case "Debian":
		typ = "deb"
		distro("debian")
	case "Ubuntu":
		typ = "deb"
		distro("ubuntu")
	case "Alpine":
		typ = "apk"
		distro("alpine")
	}
	var b strings.Builder
	b.WriteString("pkg:" + typ + "/")
	for _, n := range namespace {
		if n != "" {
			b.WriteString(escape(n) + "/")
		}
	}
	b.WriteString(escape(name))
	if version != "" {
		b.WriteString("@" + escape(version))
	}
	if len(qualifiers) > 0 {
		b.WriteString("?" + strings.Join(qualifiers, "&"))
	}
	return b.String()
}

// escape percent-encodes all but the characters a package URL leaves as
// they are: letters, digits, ".", "-", "_", "~" and ":".
func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte(".-_~:", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}
