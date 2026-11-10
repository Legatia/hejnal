package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

type file struct {
	name string
	data []byte
	mode int64
}

func tarOf(t *testing.T, files []file) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(f.data)
	}
	tw.Close()
	return b.Bytes()
}

func gz(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

const dpkg = `Package: libssl3
Status: install ok installed
Source: openssl (3.0.9-1)
Version: 3.0.9-1

Package: bash
Status: install ok installed
Version: 5.2.15-2+b2

Package: removed
Status: deinstall ok config-files
Version: 1.0
`

var (
	linuxProgOnce sync.Once
	linuxProg     []byte
	linuxProgErr  error
)

// goProgram returns a Linux Go program, as images hold: the test binary
// itself on Linux, or elsewhere (where it is Mach-O or PE) a small one
// built for Linux.
func goProgram(t *testing.T) []byte {
	t.Helper()
	if runtime.GOOS == "linux" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		prog, err := os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
		return prog
	}
	linuxProgOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			linuxProgErr = err
			return
		}
		dir, err := os.MkdirTemp("", "hejnal-goprog")
		if err != nil {
			linuxProgErr = err
			return
		}
		defer os.RemoveAll(dir)
		os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/tool\n\ngo 1.22\n"), 0o600)
		os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600)
		cmd := exec.Command(goTool, "build", "-o", "tool", ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
		if out, err := cmd.CombinedOutput(); err != nil {
			linuxProgErr = fmt.Errorf("%v: %s", err, out)
			return
		}
		linuxProg, linuxProgErr = os.ReadFile(filepath.Join(dir, "tool"))
	})
	if linuxProgErr != nil {
		t.Skipf("cannot build a Linux Go program here: %v", linuxProgErr)
	}
	return linuxProg
}

func layers(t *testing.T) [][]byte {
	prog := goProgram(t)
	one := tarOf(t, []file{
		{name: "etc/os-release", data: []byte("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n")},
		{name: "var/lib/dpkg/status", data: []byte(dpkg)},
		{name: "app/package-lock.json", data: []byte(`{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`)},
		{name: "usr/local/bin/tool", data: prog, mode: 0o755},
		{name: "opt/old/bin/gone", data: prog, mode: 0o755},
	})
	two := tarOf(t, []file{
		{name: "app/.wh.package-lock.json"},
		{name: "opt/.wh.old"},
		{name: "usr/lib/python3/site-packages/Requests-2.25.1.dist-info/METADATA", data: []byte("Metadata-Version: 2.1\nName: Requests\nVersion: 2.25.1\n\nlong description\nVersion: 9\n")},
		{name: "app/node_modules/minimist/package.json", data: []byte(`{"name":"minimist","version":"1.2.5"}`)},
	})
	return [][]byte{one, gz(two)}
}

func summary(img *Image) string {
	var out []string
	for _, p := range img.Packages {
		if p.Ecosystem == "Go" && p.Name != "stdlib" {
			continue // the test binary's own modules vary
		}
		v := p.Version
		if p.Name == "stdlib" {
			v = "*"
		}
		out = append(out, fmt.Sprintf("%s %s %s %s", p.Ecosystem, p.Name, v, p.File))
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

const want = `Debian:12 bash 5.2.15-2+b2 /var/lib/dpkg/status
Debian:12 openssl 3.0.9-1 /var/lib/dpkg/status
Go stdlib * /usr/local/bin/tool
PyPI requests 2.25.1 /usr/lib/python3/site-packages/Requests-2.25.1.dist-info
npm minimist 1.2.5 /app/node_modules/minimist`

func TestDockerSave(t *testing.T) {
	ls := layers(t)
	var files []file
	var names []string
	for i, l := range ls {
		n := fmt.Sprintf("layer%d/layer.tar", i)
		names = append(names, n)
		files = append(files, file{name: n, data: l})
	}
	m, _ := json.Marshal([]map[string]any{{"Config": "config.json", "RepoTags": []string{"acme/web:1.2"}, "Layers": names}})
	files = append([]file{{name: "manifest.json", data: m}}, files...)
	p := filepath.Join(t.TempDir(), "img.tar")
	os.WriteFile(p, tarOf(t, files), 0o600)
	img, err := Read(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if img.Name != "acme/web:1.2" || img.OS != "Debian:12" || len(img.Notes) != 0 {
		t.Errorf("image = %q %q %v", img.Name, img.OS, img.Notes)
	}
	if got := summary(img); got != want {
		t.Errorf("packages:\n%s\nwant:\n%s", got, want)
	}
	for _, p := range img.Packages {
		if p.Name == "openssl" && p.Binary != "libssl3" {
			t.Errorf("binary %q", p.Binary)
		}
	}
}

func TestOCILayout(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755)
	put := func(data []byte) string {
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		os.WriteFile(filepath.Join(dir, "blobs", "sha256", h), data, 0o600)
		return "sha256:" + h
	}
	var descs []map[string]any
	for _, l := range layers(t) {
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": put(l)})
	}
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "layers": descs})
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"digest": put(man), "annotations": map[string]string{"org.opencontainers.image.ref.name": "1.2"}}}})
	os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o600)
	img, err := Read(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := summary(img); got != want || img.Name != "1.2" {
		t.Errorf("OCI layout %q:\n%s", img.Name, got)
	}
	// The same layout as a tar archive.
	var files []file
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			data, _ := os.ReadFile(p)
			files = append(files, file{name: filepath.ToSlash(rel), data: data})
		}
		return nil
	})
	arch := filepath.Join(t.TempDir(), "oci.tar")
	os.WriteFile(arch, tarOf(t, files), 0o600)
	img, err = Read(context.Background(), arch)
	if err != nil {
		t.Fatal(err)
	}
	if got := summary(img); got != want {
		t.Errorf("OCI archive:\n%s", got)
	}
}

func TestAlpineAndUnknown(t *testing.T) {
	apk := "C:Q1x\nP:libcrypto3\nV:3.1.4-r1\no:openssl\n\nP:busybox\nV:1.36.1-r15\n"
	l := tarOf(t, []file{{name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.19.1\n")}, {name: "lib/apk/db/installed", data: []byte(apk)}})
	m, _ := json.Marshal([]map[string]any{{"Layers": []string{"l/layer.tar"}}})
	p := filepath.Join(t.TempDir(), "a.tar")
	os.WriteFile(p, tarOf(t, []file{{name: "manifest.json", data: m}, {name: "l/layer.tar", data: l}}), 0o600)
	img, err := Read(context.Background(), p)
	if err != nil || img.OS != "Alpine:v3.19" || summary(img) != "Alpine:v3.19 busybox 1.36.1-r15 /lib/apk/db/installed\nAlpine:v3.19 openssl 3.1.4-r1 /lib/apk/db/installed" {
		t.Errorf("alpine: %v %q\n%s", err, img.OS, summary(img))
	}
	l = tarOf(t, []file{{name: "etc/os-release", data: []byte("ID=fedora\nVERSION_ID=39\nPRETTY_NAME=\"Fedora Linux 39\"\n")}, {name: "var/lib/dpkg/status", data: []byte(dpkg)}})
	os.WriteFile(p, tarOf(t, []file{{name: "manifest.json", data: m}, {name: "l/layer.tar", data: l}}), 0o600)
	img, err = Read(context.Background(), p)
	if err != nil || len(img.Packages) != 0 || len(img.Notes) != 1 || !strings.Contains(img.Notes[0], "Fedora") {
		t.Errorf("unknown distribution: %v %+v", err, img)
	}
	// Paths that climb out of the image stay inside it.
	if clean("../../etc/passwd") != "etc/passwd" || clean("/") != "" {
		t.Error("clean")
	}
	if _, err := Read(context.Background(), filepath.Join(t.TempDir(), "missing.tar")); err == nil {
		t.Error("no error for a missing file")
	}
}

func TestSecurityUpdateVersions(t *testing.T) {
	// Packages patched by a Debian or Ubuntu security update must be kept.
	pkgs := parseDpkg([]byte("Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.15-1~deb12u1)\nVersion: 3.0.15-1~deb12u1\n\nPackage: openssh-client\nStatus: install ok installed\nSource: openssh\nVersion: 1:8.9p1-3ubuntu0.10~22.04\n"), "Debian:12", "/var/lib/dpkg/status")
	got := cleanPackages(pkgs)
	if len(got) != 2 || got[0].Version != "1:8.9p1-3ubuntu0.10~22.04" || got[1].Version != "3.0.15-1~deb12u1" {
		t.Errorf("security updates dropped: %+v", got)
	}
}
