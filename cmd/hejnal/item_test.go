package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// idsByKey returns the ID of each saved item, by a word of its key.
func idsByKey(t *testing.T, fs []match.Finding) func(part string) string {
	t.Helper()
	return func(part string) string {
		for _, g := range match.Groups(fs) {
			if strings.Contains(g.Key, part) || strings.Contains(g.Findings[0].Key, part) {
				return g.ID()
			}
		}
		t.Fatalf("no item with %q in its key", part)
		return ""
	}
}

func TestLiveItem(t *testing.T) {
	h := newHarness(t)
	if code, out, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run exit = %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	snap, err := state.Store{Dir: h.state}.LoadFindings()
	if err != nil {
		t.Fatal(err)
	}
	id := idsByKey(t, snap.Findings)
	php, wordpress := id("|php"), id("|wordpress")
	before := h.stateFiles()

	code, out, errOut := h.run(h.liveArgs("-item", php, h.siteURL)...)
	if code != exitFindings || !strings.Contains(out, "Item "+php+" is still found: ") || !strings.Contains(out, "PHP on 127.0.0.1") || !strings.Contains(out, "  at "+h.siteURL) {
		t.Fatalf("while the item is there: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
	}
	if strings.Contains(out, "WordPress") {
		t.Errorf("-item lists other items:\n%s", out)
	}

	// The check cannot tell without the part that found the item.
	code, out, errOut = h.run(h.liveArgs("-item", php, "-no-checks", h.siteURL)...)
	if code != exitFindings {
		t.Fatalf("-no-checks while the item is there: exit = %d, want %d\n%s\n%s", code, exitFindings, out, errOut)
	}

	h.setPHP("-")
	code, out, errOut = h.run(h.liveArgs("-item", php, h.siteURL)...)
	if code != exitOK || !strings.Contains(out, "Item "+php+" is no longer found: ") {
		t.Fatalf("once PHP is gone: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
	// Another item being there does not make this one found.
	if code, out, _ = h.run(h.liveArgs("-item", wordpress, h.siteURL)...); code != exitFindings || !strings.Contains(out, "WordPress") {
		t.Errorf("the other item: exit = %d, want %d\n%s", code, exitFindings, out)
	}
	code, out, errOut = h.run(h.liveArgs("-item", php, "-no-checks", h.siteURL)...)
	if code != exitError || out != "" || !strings.Contains(errOut, "cannot tell whether item "+php+" is still there: this check left out the fixed paths") {
		t.Errorf("-no-checks once PHP is gone: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitError, out, errOut)
	}

	code, out, errOut = h.run(h.liveArgs("-item", "00000000", h.siteURL)...)
	if code != exitOK || !strings.Contains(out, "Item 00000000 is not found.") || !strings.Contains(errOut, "no saved result lists this ID") {
		t.Errorf("an unknown ID: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
	code, _, errOut = h.run(h.liveArgs("-item", "PHP", h.siteURL)...)
	if code != exitError || !strings.Contains(errOut, `-item "PHP" is not an item's ID`) {
		t.Errorf("a bad ID: exit = %d, want %d\n%s", code, exitError, errOut)
	}

	after := h.stateFiles()
	for name, data := range after {
		if old, ok := before[name]; !ok {
			t.Errorf("-item wrote %s", name)
		} else if old != data {
			t.Errorf("-item changed %s", name)
		}
	}
}

func TestCodeScanItem(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "shop")
	lock := func(version string) string {
		return `{"packages":{"node_modules/lodash":{"version":"` + version + `"},"node_modules/react":{"version":"18.2.0"}}}`
	}
	writeFiles(t, proj, map[string]string{
		"package-lock.json": lock("4.17.20"),
		"infra/main.tf":     "resource \"aws_security_group\" \"ssh\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
		"config/app.env":    "STRIPE_KEY=sk_" + "live_" + strings.Repeat("4eC39HqLyjWDarjtT1zdp7dc", 2) + "\n",
	})
	stateDir := filepath.Join(dir, "state")
	osvSrv := fakeOSV(t)
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut)
		a.now = func() time.Time { return testNow }
		a.osvURL = osvSrv.URL
		code := a.run(context.Background(), append([]string{"code", "scan", "-kev-file", kevSample, "-no-euvd", "-no-epss"}, args...))
		return code, out.String(), errOut.String()
	}

	// Before anything is saved, the check reads no key and makes none.
	code, out, errOut := run("-state", stateDir, "-item", "00000000", proj)
	if code != exitOK || !strings.Contains(out, "Item 00000000 is not found.") || !strings.Contains(errOut, "no saved result lists this ID") {
		t.Fatalf("an unknown ID: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, out, errOut)
	}
	if entries, err := os.ReadDir(stateDir); err == nil {
		for _, e := range entries {
			if e.Name() != "cache" {
				t.Errorf("-item wrote %s to the state directory", e.Name())
			}
		}
	}

	if code, out, errOut := run("-state", stateDir, "-save", "-fail-on", "none", proj); code != exitOK {
		t.Fatalf("code scan -save: exit %d\n%s\n%s", code, out, errOut)
	}
	scans, err := state.Store{Dir: stateDir}.LoadCodeScans()
	if err != nil || len(scans) != 1 {
		t.Fatalf("saved scans: %v, %v", scans, err)
	}
	id := idsByKey(t, scans[0].Findings)
	lodash, secret, group := id("lodash"), id("secret|"), id("misconfig|")
	saved, err := os.ReadFile(filepath.Join(stateDir, "code", "shop.json"))
	if err != nil {
		// The file's name is the store's business; the scan was loaded above.
		saved = nil
	}

	item := func(args ...string) (int, string, string) {
		return run(append([]string{"-state", stateDir}, args...)...)
	}
	code, out, errOut = item("-item", lodash, proj)
	if code != exitFindings || !strings.Contains(out, "Item "+lodash+" is still found: lodash 4.17.20 (npm) in shop") || !strings.Contains(out, "  at package-lock.json") {
		t.Fatalf("while the package is there: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
	}
	if strings.Contains(out, "aws_security_group") || strings.Contains(out, "app.env") {
		t.Errorf("-item lists other items:\n%s", out)
	}
	// The secret keeps the ID the saved result gave it.
	if code, out, errOut = item("-item", secret, proj); code != exitFindings || !strings.Contains(out, "config/app.env:1") {
		t.Fatalf("while the secret is there: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
	}
	if strings.Contains(out+errOut, "4eC39HqLyjWDarjtT1zdp7dc") {
		t.Errorf("the whole secret is shown:\n%s\n%s", out, errOut)
	}

	// A scan that leaves out what finds the item cannot tell, and neither
	// can one of another directory.
	if code, _, errOut = item("-item", lodash, "-no-deps", proj); code != exitError || !strings.Contains(errOut, "cannot tell whether item "+lodash+" is still there: the scan did not check dependencies") {
		t.Errorf("-no-deps: exit = %d, want %d\n%s", code, exitError, errOut)
	}
	elsewhere := filepath.Join(dir, "elsewhere")
	writeFiles(t, elsewhere, map[string]string{"README.md": "nothing here\n"})
	if code, _, errOut = item("-item", lodash, "-project", "shop", elsewhere); code != exitError || !strings.Contains(errOut, "package-lock.json, where the item was found, is not in what was scanned") {
		t.Errorf("another directory: exit = %d, want %d\n%s", code, exitError, errOut)
	}
	if code, _, errOut = item("-item", lodash, elsewhere); code != exitError || !strings.Contains(errOut, `the item was found in project "shop", and this scan is of project "elsewhere"`) {
		t.Errorf("another project: exit = %d, want %d\n%s", code, exitError, errOut)
	}

	for _, flag := range [][]string{{"-save"}, {"-upload", "https://cloud.example"}, {"-sbom", filepath.Join(dir, "bom.json")}, {"-out", filepath.Join(dir, "out.txt")}} {
		code, _, errOut = item(append([]string{"-item", lodash}, append(flag, proj)...)...)
		if code != exitError || !strings.Contains(errOut, "-item only says whether one item is still found: leave out "+flag[0]) {
			t.Errorf("%s with -item: exit = %d, want %d\n%s", flag[0], code, exitError, errOut)
		}
	}
	if code, _, errOut = item("-item", "lodash", proj); code != exitError || !strings.Contains(errOut, `-item "lodash" is not an item's ID`) {
		t.Errorf("a bad ID: exit = %d, want %d\n%s", code, exitError, errOut)
	}

	// The fixes: an upgrade, a rule narrowed, a file with a secret deleted.
	writeFiles(t, proj, map[string]string{
		"package-lock.json": lock("4.17.21"),
		"infra/main.tf":     "resource \"aws_security_group\" \"ssh\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"10.0.0.0/8\"]\n  }\n}\n",
	})
	if err := os.Remove(filepath.Join(proj, "config", "app.env")); err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{"package": lodash, "rule": group, "secret": secret} {
		code, out, errOut = item("-item", id, proj)
		if code != exitOK || !strings.Contains(out, "Item "+id+" is no longer found: ") {
			t.Errorf("the %s, fixed: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", name, code, exitOK, out, errOut)
		}
	}
	// Without the key the saved secret's ID cannot be made again.
	keyless := filepath.Join(dir, "keyless")
	if err := os.CopyFS(keyless, os.DirFS(stateDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(keyless, "leaks.key")); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut = run("-state", keyless, "-item", secret, proj); code != exitError || !strings.Contains(errOut, "could not use the key in the state directory") {
		t.Errorf("a secret without the key: exit = %d, want %d\n%s", code, exitError, errOut)
	}
	if _, err := os.Stat(filepath.Join(keyless, "leaks.key")); err == nil {
		t.Error("-item made a key")
	}

	// -item saved nothing: the saved result is as the first scan left it.
	if saved != nil {
		if now, _ := os.ReadFile(filepath.Join(stateDir, "code", "shop.json")); !bytes.Equal(now, saved) {
			t.Error("-item changed the saved result")
		}
	}
	if scans, err := (state.Store{Dir: stateDir}).LoadCodeScans(); err != nil || len(scans) != 1 || len(scans[0].Findings) < 3 {
		t.Errorf("the saved result changed: %v, %v", scans, err)
	}
}

// A change to a version that still has an advisory is not a fix.
func TestCodeScanItemMoved(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "shop")
	lock := func(version string) map[string]string {
		return map[string]string{"package-lock.json": `{"packages":{"node_modules/lodash":{"version":"` + version + `"}}}`}
	}
	writeFiles(t, proj, lock("4.17.20"))
	stateDir := filepath.Join(dir, "state")
	osvSrv := fakeOSV(t)
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut)
		a.now = func() time.Time { return testNow }
		a.osvURL = osvSrv.URL
		code := a.run(context.Background(), append([]string{"code", "scan", "-state", stateDir, "-kev-file", kevSample, "-no-euvd", "-no-epss", "-no-secrets"}, args...))
		return code, out.String(), errOut.String()
	}
	if code, out, errOut := run("-save", "-fail-on", "none", proj); code != exitOK {
		t.Fatalf("code scan -save: exit %d\n%s\n%s", code, out, errOut)
	}
	scans, err := state.Store{Dir: stateDir}.LoadCodeScans()
	if err != nil || len(scans) != 1 {
		t.Fatalf("saved scans: %v, %v", scans, err)
	}
	id := idsByKey(t, scans[0].Findings)("lodash")

	writeFiles(t, proj, lock("4.17.19"))
	code, out, errOut := run("-item", id, proj)
	if code != exitFindings || !strings.Contains(out, "Item "+id+" is not fixed: it is now item ") || !strings.Contains(out, "lodash 4.17.19 (npm) in shop") {
		t.Fatalf("another version with an advisory: exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFindings, out, errOut)
	}
	if strings.Contains(out, "Item "+id+" is not fixed: it is now item "+id) {
		t.Errorf("the item that took its place has the same ID:\n%s", out)
	}
}
