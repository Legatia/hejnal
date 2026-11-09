package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOSV answers for lodash, log4j-core, an OpenSSL Debian package and a
// malicious npm package.
func fakeOSV(t *testing.T) *httptest.Server {
	adv := map[string]string{
		"GHSA-35jh-r3h4-6jhm": `{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash","modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`,
		"GHSA-jfh8-c2jp-5v3q": `{"id":"GHSA-jfh8-c2jp-5v3q","aliases":["CVE-2021-44228"],"summary":"Remote code injection in Log4j","modified":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`,
		"MAL-2025-7":          `{"id":"MAL-2025-7","summary":"Malicious code in evil-pkg (npm)","modified":"2025-01-01T00:00:00Z"}`,
		"DSA-5532-1":          `{"id":"DSA-5532-1","aliases":["CVE-2023-5363"],"summary":"openssl security update","modified":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]}]}`,
	}
	hits := map[string]string{"npm/lodash/4.17.20": "GHSA-35jh-r3h4-6jhm", "Maven/org.apache.logging.log4j:log4j-core/2.14.1": "GHSA-jfh8-c2jp-5v3q",
		"npm/evil-pkg/1.0.0": "MAL-2025-7", "Debian:12/openssl/3.0.9-1": "DSA-5532-1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string }
					Version string
				}
			}
			json.NewDecoder(r.Body).Decode(&req)
			var res []map[string]any
			for _, q := range req.Queries {
				if id, ok := hits[q.Package.Ecosystem+"/"+q.Package.Name+"/"+q.Version]; ok {
					res = append(res, map[string]any{"vulns": []map[string]any{{"id": id, "modified": "2024-01-01T00:00:00Z"}}})
				} else {
					res = append(res, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
			return
		}
		if a, ok := adv[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]; ok {
			io.WriteString(w, a)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func imageTar(t *testing.T, path string) {
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	for name, data := range map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": "Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.9-1\n",
	} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		io.WriteString(tw, data)
	}
	tw.Close()
	var img bytes.Buffer
	tw = tar.NewWriter(&img)
	m := `[{"RepoTags":["acme/api:1.0"],"Layers":["l/layer.tar"]}]`
	for _, f := range []struct {
		name string
		data []byte
	}{{"manifest.json", []byte(m)}, {"l/layer.tar", layer.Bytes()}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		tw.Write(f.data)
	}
	tw.Close()
	os.WriteFile(path, img.Bytes(), 0o600)
}

func TestCodeScan(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "shop")
	writeFiles(t, proj, map[string]string{
		"package-lock.json": `{"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/evil-pkg":{"version":"1.0.0","dev":true},"node_modules/react":{"version":"18.2.0"}}}`,
		"gradle.lockfile":   "org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\n",
		"infra/main.tf":     "resource \"aws_security_group\" \"ssh\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
		"config/app.env":    "STRIPE_KEY=sk_" + "live_" + strings.Repeat("4eC39HqLyjWDarjtT1zdp7dc", 2) + "\n",
	})
	img := filepath.Join(dir, "api.tar")
	imageTar(t, img)
	kevFile := filepath.Join(dir, "kev.json")
	os.WriteFile(kevFile, []byte(`{"catalogVersion":"2026.11.01","vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dateAdded":"2021-12-10","dueDate":"2021-12-24"}]}`), 0o600)
	osvSrv := fakeOSV(t)
	var mu sync.Mutex
	var uploaded []byte
	var auth string
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		uploaded, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/code-results" {
			http.NotFound(w, r)
		}
	}))
	defer cloud.Close()
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut)
		a.now = func() time.Time { return testNow }
		a.osvURL = osvSrv.URL
		code := a.run(context.Background(), append([]string{"code", "scan", "-state", filepath.Join(dir, "state"), "-kev-file", kevFile, "-no-euvd", "-no-epss"}, args...))
		return code, out.String(), errOut.String()
	}

	code, out, errOut := run(proj, "-image", img)
	if code != exitFindings {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Checked shop: 5 packages",
		"evil-pkg 1.0.0 (npm) in shop",
		"→ Remove evil-pkg now",
		"org.apache.logging.log4j:log4j-core 2.14.1 (Maven) in shop: CVE-2021-44228",
		"→ Upgrade org.apache.logging.log4j:log4j-core to 2.15.0 or later",
		"aws_security_group.ssh opens an admin or database port to the internet",
		"at infra/main.tf:2",
		"config/app.env:1",
		"Low: 2 more items",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "react") || strings.Contains(out, "4eC39HqLyjWDarjtT1zdp7dc") {
		t.Errorf("a clean package or a whole secret in the output:\n%s", out)
	}

	// SARIF for GitHub code scanning.
	code, out, _ = run(proj, "-format", "sarif", "-fail-on", "none")
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID    string
				Level     string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &sarif); err != nil || code != exitOK {
		t.Fatalf("SARIF (exit %d): %v\n%s", code, err, out)
	}
	byRule := map[string]string{}
	for _, r := range sarif.Runs[0].Results {
		l := r.Locations[0].PhysicalLocation
		byRule[r.RuleID] = fmt.Sprintf("%s %s:%d", r.Level, l.ArtifactLocation.URI, l.Region.StartLine)
	}
	if byRule["GHSA-jfh8-c2jp-5v3q"] != "error gradle.lockfile:1" || byRule["iac/open-admin-port"] != "error infra/main.tf:2" || byRule["MAL-2025-7"] == "" {
		t.Errorf("SARIF results = %v", byRule)
	}

	// Save for later runs, and upload the results.
	code, _, errOut = run(proj, "-save", "-format", "json", "-fail-on", "none", "-project", "Shop Web", "-upload", cloud.URL)
	if code != exitError || !strings.Contains(errOut, "HEJNAL_UPLOAD_TOKEN") {
		t.Errorf("upload without a token: %d %s", code, errOut)
	}
	t.Setenv("HEJNAL_UPLOAD_TOKEN", "hjup_test")
	code, _, errOut = run(proj, "-save", "-format", "json", "-fail-on", "none", "-project", "Shop Web", "-upload", cloud.URL)
	if code != exitOK || !strings.Contains(errOut, "Saved to") {
		t.Fatalf("save and upload: %d\n%s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "code", "Shop-Web.json")); err != nil {
		t.Errorf("not saved: %v", err)
	}
	mu.Lock()
	if auth != "Bearer hjup_test" || !bytes.Contains(uploaded, []byte(`"project": "Shop Web"`)) && !bytes.Contains(uploaded, []byte(`"project":"Shop Web"`)) || bytes.Contains(uploaded, []byte("4eC39HqLyjWDarjtT1zdp7dc")) {
		t.Errorf("upload: %q %s", auth, uploaded)
	}
	mu.Unlock()
	if code, _, errOut := run(proj, "-upload", "http://hejnal.example"); code != exitError || !strings.Contains(errOut, "https") {
		t.Errorf("plain HTTP upload: %d %s", code, errOut)
	}
	if code, _, _ := run(proj, "-offline"); code != exitError {
		t.Errorf("offline dependency check did not fail")
	}
	if code, out, _ := run(proj, "-offline", "-no-deps", "-fail-on", "none"); code != exitOK || strings.Contains(out, "lodash") {
		t.Errorf("-no-deps: %d\n%s", code, out)
	}
}

// A saved code scan joins the next run's fix list and alerts, scored
// against the lists of exploited flaws of that run.
func TestSavedCodeScanJoinsRuns(t *testing.T) {
	h := newHarness(t)
	proj := filepath.Join(h.dir, "shop")
	writeFiles(t, proj, map[string]string{"gradle.lockfile": "org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\n"})
	osvSrv := fakeOSV(t)
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.now = func() time.Time { return testNow }
	a.osvURL = osvSrv.URL
	if code := a.run(context.Background(), []string{"code", "scan", "-state", h.state, "-kev-file", kevSample, "-no-euvd", "-no-epss", "-no-secrets", "-save", "-fail-on", "none", proj}); code != exitOK {
		t.Fatalf("code scan: %d\n%s", code, errOut.String())
	}
	code, stdout, stderr := h.run(h.runArgs()...)
	if code != exitOK {
		t.Fatalf("run: %d\n%s\n%s", code, stdout, stderr)
	}
	fix, err := os.ReadFile(filepath.Join(h.state, "fixlist.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"org.apache.logging.log4j:log4j-core 2.14.1 (Maven) in shop", "GHSA-jfh8-c2jp-5v3q", "fixed in `2.15.0`", "**How sure:**"} {
		if !strings.Contains(string(fix), want) {
			t.Errorf("fix list lacks %q:\n%s", want, fix)
		}
	}
}
