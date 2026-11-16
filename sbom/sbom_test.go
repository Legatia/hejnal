package sbom

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/deps"
)

func TestPURL(t *testing.T) {
	for _, c := range []struct {
		p    deps.Package
		want string
	}{
		{deps.Package{Ecosystem: deps.Npm, Name: "lodash", Version: "4.17.20"}, "pkg:npm/lodash@4.17.20"},
		{deps.Package{Ecosystem: deps.Npm, Name: "@babel/core", Version: "7.24.0"}, "pkg:npm/%40babel/core@7.24.0"},
		{deps.Package{Ecosystem: deps.PyPI, Name: "Flask_Login", Version: "0.6.3"}, "pkg:pypi/flask-login@0.6.3"},
		{deps.Package{Ecosystem: deps.Go, Name: "github.com/Azure/go-autorest", Version: "14.2.0+incompatible"}, "pkg:golang/github.com/azure/go-autorest@v14.2.0%2Bincompatible"},
		{deps.Package{Ecosystem: deps.Go, Name: "golang.org/x/net", Version: "0.0.0-20240101120000-abcdef123456"}, "pkg:golang/golang.org/x/net@v0.0.0-20240101120000-abcdef123456"},
		{deps.Package{Ecosystem: deps.Go, Name: "stdlib", Version: "1.22.3"}, "pkg:golang/stdlib@1.22.3"},
		{deps.Package{Ecosystem: deps.Go, Name: "example.com/app", Version: "(devel)"}, "pkg:golang/example.com/app@%28devel%29"},
		{deps.Package{Ecosystem: deps.Cargo, Name: "serde", Version: "1.0.197"}, "pkg:cargo/serde@1.0.197"},
		{deps.Package{Ecosystem: deps.RubyGems, Name: "rails", Version: "7.1.3"}, "pkg:gem/rails@7.1.3"},
		{deps.Package{Ecosystem: deps.Packagist, Name: "Symfony/HTTP-Kernel", Version: "6.4.4"}, "pkg:composer/symfony/http-kernel@6.4.4"},
		{deps.Package{Ecosystem: deps.Maven, Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"}, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{deps.Package{Ecosystem: deps.NuGet, Name: "Newtonsoft.Json", Version: "13.0.3"}, "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{deps.Package{Ecosystem: "Debian:12", Name: "openssl", Binary: "libssl3", Version: "3.0.9-1"}, "pkg:deb/debian/libssl3@3.0.9-1?distro=debian-12&upstream=openssl"},
		{deps.Package{Ecosystem: "Debian:12", Name: "shadow", Binary: "passwd", Version: "1:4.13+dfsg1-1+b1"}, "pkg:deb/debian/passwd@1:4.13%2Bdfsg1-1%2Bb1?distro=debian-12&upstream=shadow"},
		{deps.Package{Ecosystem: "Debian:12", Name: "libsigc++-2.0", Binary: "libsigc++-2.0-0v5", Version: "2.12.0-1~deb12u1"}, "pkg:deb/debian/libsigc%2B%2B-2.0-0v5@2.12.0-1~deb12u1?distro=debian-12&upstream=libsigc%2B%2B-2.0"},
		{deps.Package{Ecosystem: "Ubuntu:22.04:LTS", Name: "curl", Binary: "curl", Version: "7.81.0-1ubuntu1.15"}, "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15?distro=ubuntu-22.04"},
		{deps.Package{Ecosystem: "Alpine:v3.19", Name: "openssl", Binary: "libcrypto3", Version: "3.1.4-r5"}, "pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19&upstream=openssl"},
		{deps.Package{Ecosystem: "Hex", Name: "phoenix", Version: "1.7.0"}, "pkg:generic/phoenix@1.7.0"},
		{deps.Package{Ecosystem: deps.Npm, Name: "left pad"}, "pkg:npm/left%20pad"},
	} {
		if got := PURL(c.p); got != c.want {
			t.Errorf("PURL(%s %s %s) = %s, want %s", c.p.Ecosystem, c.p.Name, c.p.Version, got, c.want)
		}
	}
}

// The fields CycloneDX 1.6 allows where this package writes; its schema
// refuses any other.
var allowed = map[string][]string{
	"document":   {"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"},
	"metadata":   {"timestamp", "tools", "component"},
	"tools":      {"components"},
	"component":  {"type", "bom-ref", "group", "name", "version", "scope", "purl", "externalReferences", "evidence"},
	"evidence":   {"occurrences"},
	"occurrence": {"location", "line"},
}

func checkKeys(t *testing.T, kind string, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, not an object", kind, v)
	}
	for k := range m {
		if !slices.Contains(allowed[kind], k) {
			t.Errorf("%s has the field %q", kind, k)
		}
	}
	return m
}

func TestCycloneDX(t *testing.T) {
	pkgs := []deps.Package{
		{Ecosystem: deps.Npm, Name: "react", Version: "18.2.0", File: "web/package-lock.json", Line: 40},
		{Ecosystem: deps.Npm, Name: "react", Version: "18.2.0", File: "admin/package-lock.json", Line: 12},
		{Ecosystem: deps.Npm, Name: "react", Version: "18.2.0", File: "admin/package-lock.json", Line: 12},
		{Ecosystem: deps.Npm, Name: "@types/node", Version: "20.11.0", File: "web/package-lock.json", Dev: true},
		// For tests in one place, shipped from another: it runs with the product.
		{Ecosystem: deps.Npm, Name: "debug", Version: "4.3.4", File: "web/package-lock.json", Dev: true},
		{Ecosystem: deps.Npm, Name: "debug", Version: "4.3.4", File: "admin/package-lock.json"},
		{Ecosystem: deps.Maven, Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", File: "gradle.lockfile", Line: 1},
		{Ecosystem: "Debian:12", Name: "openssl", Binary: "libssl3", Version: "3.0.9-1", File: "acme/api:1.0:/var/lib/dpkg/status"},
		{Ecosystem: deps.Npm, Name: "", Version: "1.0.0"},
	}
	var buf bytes.Buffer
	n, err := CycloneDX(&buf, pkgs, Options{Project: "shop", Time: time.Date(2026, 11, 4, 13, 0, 0, 0, time.FixedZone("CET", 3600)), ToolVersion: "0.8.0"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("%d components, want 5", n)
	}
	if strings.Contains(buf.String(), `\u0026`) {
		t.Errorf("an escaped & in a package URL:\n%s", buf.String())
	}
	var raw any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	doc := checkKeys(t, "document", raw)
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" || doc["version"] != float64(1) {
		t.Errorf("header: %v %v %v", doc["bomFormat"], doc["specVersion"], doc["version"])
	}
	// The pattern is the schema's.
	if s, _ := doc["serialNumber"].(string); !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(s) {
		t.Errorf("serialNumber = %q", s)
	}
	meta := checkKeys(t, "metadata", doc["metadata"])
	if meta["timestamp"] != "2026-11-04T12:00:00Z" {
		t.Errorf("timestamp = %v", meta["timestamp"])
	}
	tool := checkKeys(t, "component", checkKeys(t, "tools", meta["tools"])["components"].([]any)[0])
	if tool["name"] != "hejnal" || tool["version"] != "0.8.0" || tool["type"] != "application" {
		t.Errorf("tool = %v", tool)
	}
	if subject := checkKeys(t, "component", meta["component"]); subject["name"] != "shop" || subject["type"] != "application" {
		t.Errorf("metadata.component = %v", subject)
	}
	var got []string
	for _, c := range doc["components"].([]any) {
		m := checkKeys(t, "component", c)
		if m["type"] != "library" || m["bom-ref"] != m["purl"] {
			t.Errorf("component %v", m)
		}
		line := []string{m["purl"].(string)}
		for _, k := range []string{"group", "name", "version", "scope"} {
			if v, ok := m[k].(string); ok {
				line = append(line, k+"="+v)
			}
		}
		for _, o := range checkKeys(t, "evidence", m["evidence"])["occurrences"].([]any) {
			oc := checkKeys(t, "occurrence", o)
			at := oc["location"].(string)
			if l, ok := oc["line"].(float64); ok {
				at += ":" + strconv.Itoa(int(l))
			}
			line = append(line, at)
		}
		got = append(got, strings.Join(line, " "))
	}
	want := []string{
		"pkg:deb/debian/libssl3@3.0.9-1?distro=debian-12&upstream=openssl name=libssl3 version=3.0.9-1 acme/api:1.0:/var/lib/dpkg/status",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 group=org.apache.logging.log4j name=log4j-core version=2.14.1 gradle.lockfile:1",
		"pkg:npm/%40types/node@20.11.0 group=@types name=node version=20.11.0 scope=excluded web/package-lock.json",
		"pkg:npm/debug@4.3.4 name=debug version=4.3.4 admin/package-lock.json web/package-lock.json",
		"pkg:npm/react@18.2.0 name=react version=18.2.0 admin/package-lock.json:12 web/package-lock.json:40",
	}
	if !slices.Equal(got, want) {
		t.Errorf("components:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCycloneDXSerials(t *testing.T) {
	write := func(o Options) string {
		var buf bytes.Buffer
		if _, err := CycloneDX(&buf, nil, o); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	a, b := write(Options{Project: "shop"}), write(Options{Project: "shop"})
	if a == b {
		t.Error("two documents share a serial number")
	}
	// A list with nothing in it is still a list.
	if !strings.Contains(a, `"components": []`) {
		t.Errorf("no empty list of components:\n%s", a)
	}
	const serial = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
	if got := write(Options{Project: "shop", Serial: serial}); !strings.Contains(got, `"serialNumber": "`+serial+`"`) || got != write(Options{Project: "shop", Serial: serial}) {
		t.Errorf("a given serial number is not kept, or the output differs between writes:\n%s", got)
	}
}
