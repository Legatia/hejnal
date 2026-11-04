package leaks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newRepo creates a git repository in a temporary directory, isolated from
// the user's and the system's git settings, and returns a function that runs
// git in it.
func newRepo(t *testing.T) (dir string, git func(args ...string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	dir = t.TempDir()
	git = func(args ...string) string {
		t.Helper()
		base := []string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
			"-c", "init.defaultBranch=main", "-C", dir}
		out, err := exec.Command("git", append(base, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	return dir, git
}

func TestScanGitHistory(t *testing.T) {
	dir, git := newRepo(t)
	ctx := context.Background()
	ghp := "ghp_" + strings.Repeat("a1B2", 9)
	npm := "npm_" + fake(alnum, 36, 500)

	writeFile(t, dir, "config.yml", "name: app\ntoken: "+ghp+"\n")
	git("add", "-A")
	git("commit", "-qm", "add config")
	added := git("rev-parse", "HEAD")
	writeFile(t, dir, "config.yml", "name: app\n")
	git("commit", "-qam", "remove the token")

	// On another branch: a line inserted into a file whose name git quotes,
	// and secrets in a skipped directory and a lockfile.
	git("checkout", "-qb", "feature")
	writeFile(t, dir, "docs/my notes ż.txt", "one\ntwo\nthree\n")
	git("add", "-A")
	git("commit", "-qm", "notes")
	writeFile(t, dir, "docs/my notes ż.txt", "one\nnpm "+npm+"\ntwo\nthree\n")
	git("commit", "-qam", "insert a line")
	inserted := git("rev-parse", "HEAD")
	writeFile(t, dir, "node_modules/x/index.js", "token: "+ghp+"\n")
	writeFile(t, dir, "yarn.lock", "token: "+ghp+"\n")
	git("add", "-A")
	git("commit", "-qm", "dependencies")
	git("checkout", "-q", "main")

	if leaks, err := ScanDir(ctx, dir, Options{}); err != nil || len(leaks) != 0 {
		t.Fatalf("the working tree: got %+v, %v; want nothing", leaks, err)
	}
	leaks, err := ScanGitHistory(ctx, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Leak{
		{RuleID: "github-token", File: "config.yml", Line: 2, Commit: added, Fingerprint: fingerprint(ghp)},
		{RuleID: "npm-token", File: "docs/my notes ż.txt", Line: 2, Commit: inserted, Fingerprint: fingerprint(npm)},
	}
	if len(leaks) != len(want) {
		t.Fatalf("got %+v, want %+v", leaks, want)
	}
	for i, w := range want {
		l := leaks[i]
		if l.RuleID != w.RuleID || l.File != w.File || l.Line != w.Line || l.Commit != w.Commit || l.Fingerprint != w.Fingerprint {
			t.Errorf("leak %d = %+v, want %+v", i, l, w)
		}
	}
}

func TestScanGitHistoryReportsOldestCommit(t *testing.T) {
	dir, git := newRepo(t)
	key := "AKIA" + fake(upper+digits, 16, 501)
	writeFile(t, dir, "f.txt", "key: "+key+"\n")
	git("add", "-A")
	git("commit", "-qm", "one")
	first := git("rev-parse", "HEAD")
	writeFile(t, dir, "f.txt", "\n")
	git("commit", "-qam", "two")
	writeFile(t, dir, "f.txt", "\n\nkey: "+key+"\n")
	git("commit", "-qam", "three")

	leaks, err := ScanGitHistory(context.Background(), dir, Options{})
	if err != nil || len(leaks) != 1 || leaks[0].Commit != first || leaks[0].Line != 1 {
		t.Errorf("got %+v, %v; want the key once, from the first commit", leaks, err)
	}
}

func TestScanGitHistoryErrors(t *testing.T) {
	dir, git := newRepo(t)
	ctx := context.Background()
	if leaks, err := ScanGitHistory(ctx, dir, Options{}); err != nil || len(leaks) != 0 {
		t.Errorf("empty repository: got %+v, %v", leaks, err)
	}
	writeFile(t, dir, "a.txt", strings.Repeat("some text\n", 100))
	git("add", "-A")
	git("commit", "-qm", "text")

	if _, err := ScanGitHistory(ctx, t.TempDir(), Options{}); err == nil || !strings.Contains(err.Error(), "git log failed") {
		t.Errorf("not a repository: got %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ScanGitHistory(cancelled, dir, Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: got %v", err)
	}

	defer func(old int64) { maxGitOutput = old }(maxGitOutput)
	maxGitOutput = 100
	if _, err := ScanGitHistory(ctx, dir, Options{}); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("too much output: got %v", err)
	}
	maxGitOutput = 512 << 20

	t.Setenv("PATH", "")
	if _, err := ScanGitHistory(ctx, dir, Options{}); err == nil || !strings.Contains(err.Error(), "git was not found") {
		t.Errorf("no git: got %v", err)
	}
}

func TestDiffParser(t *testing.T) {
	removed := "ghp_" + fake(alnum, 36, 502)
	added := "ghp_" + fake(alnum, 36, 503)
	key := "AKIA" + fake(upper+digits, 16, 504)
	a, b := strings.Repeat("a1", 20), strings.Repeat("b2", 20)
	log := "commit " + a + "\n\n" +
		"diff --git a/x.txt b/x.txt\n--- a/x.txt\n+++ b/x.txt\n" +
		"@@ -1,2 +1,3 @@\n" +
		"--- a/a removed line that looks like a header\n" +
		"-token: " + removed + "\n" +
		"+++ b/an added line that looks like a header\n" +
		"+token: " + added + "\n" +
		"+\\ an added line\n" +
		"\\ No newline at end of file\n" +
		"commit " + b + "\n" +
		"diff --git a/bin b/bin\nBinary files a/bin and b/bin differ\n" +
		"diff --git \"a/q\\\"uote.txt\" \"b/q\\\"uote.txt\"\n--- /dev/null\n+++ \"b/q\\\"uote.txt\"\n" +
		"@@ -0,0 +5 @@\n+key: " + key + "\n"

	p := &diffParser{opts: Options{}.withDefaults()}
	if err := p.parse(context.Background(), strings.NewReader(log)); err != nil {
		t.Fatal(err)
	}
	leaks := finish(p.s.leaks)
	if len(leaks) != 2 {
		t.Fatalf("got %+v, want 2 leaks", leaks)
	}
	if l := leaks[0]; l.File != `q"uote.txt` || l.Line != 5 || l.Commit != b || l.Fingerprint != fingerprint(key) {
		t.Errorf("got %+v", l)
	}
	if l := leaks[1]; l.File != "x.txt" || l.Line != 2 || l.Commit != a || l.Fingerprint != fingerprint(added) {
		t.Errorf("got %+v", l)
	}
}
