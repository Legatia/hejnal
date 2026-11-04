package leaks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// places lists leaks as file:line.
func places(leaks []Leak) []string {
	var out []string
	for _, l := range leaks {
		out = append(out, fmt.Sprintf("%s:%d", l.File, l.Line))
	}
	return out
}

func TestScanDir(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	secret := "GITHUB_TOKEN=" + ghp + "\n"
	root := t.TempDir()
	writeFile(t, root, "config/app.env", "# settings\n"+secret)
	writeFile(t, root, "src/deep/main.go", "package main\n\nvar x = 1\n// npm: npm_"+fake(alnum, 36, 400)+"\n")
	writeFile(t, root, "node_modules/pkg/index.js", secret)
	writeFile(t, root, "vendor/lib/x.go", secret)
	writeFile(t, root, ".git/config", secret)
	writeFile(t, root, "package-lock.json", secret)
	writeFile(t, root, "sub/go.sum", secret)
	writeFile(t, root, "bin/tool", "\x7fELF\x00\x00"+secret)
	writeFile(t, root, "big.txt", strings.Repeat("#\n", 1<<10)+secret)
	writeFile(t, root, "docs/old/notes.md", secret)
	writeFile(t, root, "fixtures/creds.txt", secret)
	outside := t.TempDir()
	writeFile(t, outside, "secret.txt", secret)
	symlinks := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")) == nil &&
		os.Symlink(outside, filepath.Join(root, "linkdir")) == nil
	ctx := context.Background()

	// Default skip dirs, 1 KiB file limit: big.txt is too large.
	leaks, err := ScanDir(ctx, root, Options{MaxFileSize: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config/app.env:2", "docs/old/notes.md:1", "fixtures/creds.txt:1", "src/deep/main.go:4"}
	if got := places(leaks); !slices.Equal(got, want) {
		t.Errorf("default options: got %v, want %v", got, want)
	}
	if leaks[0].Fingerprint != leaks[1].Fingerprint || leaks[0].RuleID != "github-token" || leaks[3].RuleID != "npm-token" {
		t.Errorf("got %+v", leaks)
	}

	// Own skip dirs replace the defaults; a name with a slash is a path.
	leaks, err = ScanDir(ctx, root, Options{SkipDirs: []string{"fixtures", "docs/old"}})
	if err != nil {
		t.Fatal(err)
	}
	want = []string{".git/config:1", "big.txt:1025", "config/app.env:2", "node_modules/pkg/index.js:1", "src/deep/main.go:4", "vendor/lib/x.go:1"}
	if got := places(leaks); !slices.Equal(got, want) {
		t.Errorf("own skip dirs: got %v, want %v", got, want)
	}

	// A single file is reported by its name.
	leaks, err = ScanDir(ctx, filepath.Join(root, "config", "app.env"), Options{})
	if err != nil || !slices.Equal(places(leaks), []string{"app.env:2"}) {
		t.Errorf("single file: got %v, %v", places(leaks), err)
	}

	if symlinks {
		// The root may itself be a link; links inside it are not followed.
		link := filepath.Join(t.TempDir(), "root")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		leaks, err = ScanDir(ctx, link, Options{MaxFileSize: 1 << 10})
		want = []string{"config/app.env:2", "docs/old/notes.md:1", "fixtures/creds.txt:1", "src/deep/main.go:4"}
		if got := places(leaks); err != nil || !slices.Equal(got, want) {
			t.Errorf("root link: got %v, %v; want %v", got, err, want)
		}
	}
}

func TestScanDirErrors(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.txt", "token: ghp_"+strings.Repeat("a1B2", 9)+"\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if leaks, err := ScanDir(ctx, root, Options{}); !errors.Is(err, context.Canceled) || leaks != nil {
		t.Errorf("cancelled: got %v, %v", leaks, err)
	}
	if _, err := ScanDir(context.Background(), filepath.Join(root, "missing"), Options{}); err == nil {
		t.Error("missing root: no error")
	}

	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read any file")
	}
	writeFile(t, root, "locked.txt", "x")
	if err := os.Chmod(filepath.Join(root, "locked.txt"), 0); err != nil {
		t.Fatal(err)
	}
	leaks, err := ScanDir(context.Background(), root, Options{})
	if err == nil || !strings.Contains(err.Error(), "skipped 1 unreadable") || len(leaks) != 1 {
		t.Errorf("unreadable file: got %v, %v; want the other file's leak and an error", places(leaks), err)
	}
}

func TestLongLines(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	npm := "npm_" + fake(alnum, 36, 401)
	akia := "AKIA" + fake(upper+digits, 16, 402)
	inOverlap := "glpat-" + fake(alnum, 20, 403)
	pad := strings.Repeat("a ", maxLinePiece)
	// ghp crosses the cut between the first and second pieces of a 3 MiB
	// line, inOverlap lies where the pieces overlap, and npm ends the line.
	line := pad[:maxLinePiece-1000] + inOverlap + strings.Repeat(" ", 1000-len(inOverlap)-20) + ghp + " " + pad + npm
	if i := strings.Index(line, ghp); i >= maxLinePiece || i+len(ghp) <= maxLinePiece {
		t.Fatalf("the token does not cross the cut")
	}
	leaks, err := ScanReader("min.js", strings.NewReader(line+"\nnext: "+akia+"\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"github-token": fingerprint(nil, ghp), "npm-token": fingerprint(nil, npm), "gitlab-token": fingerprint(nil, inOverlap)}
	if len(leaks) != 4 || leaks[3].RuleID != "aws-access-key-id" || leaks[3].Line != 2 {
		t.Fatalf("got %+v, want three leaks on line 1 and one on line 2", leaks)
	}
	for _, l := range leaks[:3] {
		if l.Line != 1 || want[l.RuleID] != l.Fingerprint {
			t.Errorf("got %+v", l)
		}
	}

	leaks, _ = ScanReader("crlf", strings.NewReader("a\r\ntoken: "+ghp+"\r\n"), Options{})
	if len(leaks) != 1 || leaks[0].Line != 2 || leaks[0].Fingerprint != fingerprint(nil, ghp) {
		t.Errorf("CRLF: got %+v", leaks)
	}
}
