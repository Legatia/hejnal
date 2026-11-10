package match

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Legatia/hejnal/deps"
	"github.com/Legatia/hejnal/epss"
	"github.com/Legatia/hejnal/iac"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/osv"
)

func advisory(t *testing.T, raw string) *osv.Vuln {
	var v osv.Vuln
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestDependencies(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	cat := &kev.Catalog{Vulnerabilities: []kev.Vulnerability{{CVEID: "CVE-2021-44228", DateAdded: "2021-12-10", DueDate: "2021-12-24", VendorProject: "Apache", Product: "Log4j2"}}}
	log4j := advisory(t, `{"id":"GHSA-jfh8-c2jp-5v3q","aliases":["CVE-2021-44228"],"summary":"Remote code injection in Log4j","modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"CRITICAL"},
		"affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`)
	lodash := advisory(t, `{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash","modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},
		"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`)
	mal := advisory(t, `{"id":"MAL-2025-1","summary":"Malicious code in evil-pkg (npm)","modified":"2025-01-01T00:00:00Z"}`)
	ms := []DepMatch{
		{deps.Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", File: "gradle.lockfile", Line: 2}, log4j},
		{deps.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", File: "web/package-lock.json"}, lodash},
		{deps.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", File: "admin/package-lock.json"}, lodash},
		{deps.Package{Ecosystem: "npm", Name: "evil-pkg", Version: "1.0.0", File: "web/package-lock.json", Dev: true}, mal},
	}
	fs := Dependencies(ms, DependencyOptions{Project: "acme", Catalog: cat, EPSS: map[string]epss.Score{"CVE-2021-23337": {EPSS: 0.02}}, Now: now})
	if len(fs) != 4 {
		t.Fatalf("%d findings", len(fs))
	}
	byName := map[string]Finding{}
	for _, f := range fs {
		byName[f.Technology] = f
	}
	if f := byName["evil-pkg"]; f.Score != 95 || f.Severity != Critical || !f.Malicious {
		t.Errorf("malicious = %+v", f)
	}
	if f := byName["org.apache.logging.log4j:log4j-core"]; f.Severity.Rank() < High.Rank() || f.FixedIn != "2.15.0" || f.CVE != "CVE-2021-44228" || len(f.ListedBy) == 0 || f.Line != 2 {
		t.Errorf("log4j = %+v", f)
	}
	if f := byName["lodash"]; f.Score != 50 || f.Severity != Medium || f.FixedIn != "4.17.21" {
		t.Errorf("lodash = %d %s %q", f.Score, f.Severity, f.FixedIn)
	}
	// One lodash item across both lockfiles.
	gs := Groups(fs)
	if len(gs) != 3 {
		t.Errorf("%d items", len(gs))
	}
	// A quiet advisory stays low; it rises once the flaw is exploited.
	quiet := Dependencies(ms[1:2], DependencyOptions{Project: "acme", Now: now})
	if quiet[0].Severity != Low {
		t.Errorf("quiet = %s", quiet[0].Severity)
	}
	RescoreDependencies(quiet, &kev.Catalog{Vulnerabilities: []kev.Vulnerability{{CVEID: "CVE-2021-23337", DateAdded: "2026-11-01"}}}, nil, now)
	if quiet[0].Severity.Rank() < High.Rank() || quiet[0].DateAdded != "2026-11-01" {
		t.Errorf("after joining the list: %+v", quiet[0])
	}
}

func TestMisconfigs(t *testing.T) {
	fs := Misconfigs("acme", []iac.Issue{{Rule: iac.RuleOpenAdminPort, Resource: "aws_security_group.b", File: "main.tf", Line: 2, Detail: "SSH (22) open to 0.0.0.0/0"}})
	if len(fs) != 1 || fs[0].Severity != High || fs[0].Kind != KindMisconfig || fs[0].Host != "acme" {
		t.Errorf("%+v", fs)
	}
}
