package leaks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// maxGitOutput is how much output from git log ScanGitHistory reads before it
// gives up: 512 MiB. It is a variable so tests can lower it.
var maxGitOutput int64 = 512 << 20

var errTooMuchOutput = errors.New("too much output")

var (
	hunkHeader = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)
	commitLine = regexp.MustCompile(`^commit ([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// gitKeepVars are the only environment variables git gets. Everything else,
// such as GIT_DIR from a hook or Hejnal's own API keys, stays out of reach of
// git and of any program a hostile repository manages to start.
var gitKeepVars = []string{
	"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP",
	"SystemRoot", "SYSTEMROOT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
}

// gitSafety are settings that override what a scanned repository's own
// .git/config may say: no signature checks, which run gpg.program; no
// file system monitor; and the first commit's changes always shown.
var gitSafety = []string{
	"-c", "log.showSignature=false",
	"-c", "log.showRoot=true",
	"-c", "core.fsmonitor=false",
	"-c", "diff.interHunkContext=0",
}

// binaryExtensions are skipped in history scans, where --text would
// otherwise print binary files in full.
var binaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".webp": true, ".bmp": true,
	".zip": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
	".jar": true, ".war": true, ".class": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".pdf": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true, ".wasm": true, ".pyc": true, ".o": true, ".a": true,
}

// ScanGitHistory scans every commit on every branch and tag of the git
// repository at repo, including secrets that later commits removed. It runs
// git log and scans only the lines each commit added. Leak.Commit is the
// commit that added the secret, Leak.File the path in that commit and
// Leak.Line the line number in the file as of that commit. When the same
// secret was added to a file more than once, the oldest commit is reported.
//
// repo must be the top directory of the repository (or a bare repository),
// not a directory inside one. Paths in Options.SkipDirs, lockfiles and
// common binary file types are skipped. ScanGitHistory needs git 2.31 or
// later on the PATH. It stops with an error after 512 MiB of git output,
// and when ctx ends.
//
// The scanned repository is treated as untrusted: git runs without
// Hejnal's environment, cannot fetch anything, and ignores repository
// settings that would start programs or hide changes.
func ScanGitHistory(ctx context.Context, repo string, opts Options) ([]Leak, error) {
	opts = opts.withDefaults()
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("leaks: git was not found on the PATH; install git to scan repository history")
	}
	if err := checkTopLevel(ctx, git, repo); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// --no-ext-diff and --no-textconv keep git from running diff and
	// conversion programs, so the scan sees the stored text. --text shows
	// files that .gitattributes marks as binary or -diff, merges are shown
	// against their first parent, and fixed prefixes override
	// diff.noprefix settings.
	args := append(slices.Clone(gitSafety), "-C", repo, "log", "-p", "--all", "--reverse",
		"--no-color", "--no-ext-diff", "--no-textconv", "--no-show-signature", "--text",
		"--diff-merges=first-parent", "--inter-hunk-context=0", "-U0",
		"--src-prefix=a/", "--dst-prefix=b/", "--format=commit %H")
	cmd := exec.CommandContext(runCtx, git, args...)
	cmd.Env = gitEnv()
	stderr := &cappedBuffer{max: 4 << 10}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("leaks: git: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("leaks: start git: %w", err)
	}
	p := &diffParser{opts: opts}
	p.s.key = opts.FingerprintKey
	perr := p.parse(ctx, &limitedReader{r: stdout, limit: maxGitOutput})
	if perr != nil {
		cancel() // stop git, which may be blocked writing to the pipe
	}
	werr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.Is(perr, errTooMuchOutput):
		return nil, fmt.Errorf("leaks: git log printed more than %d MiB; the history is too large to scan in one go", maxGitOutput>>20)
	case perr != nil:
		return nil, fmt.Errorf("leaks: read git log: %w", perr)
	case werr != nil:
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = werr.Error()
		}
		return nil, fmt.Errorf("leaks: git log failed in %s: %s", repo, msg)
	}
	return finish(p.s.leaks), nil
}

// diffParser reads git log -p output and scans the added lines.
type diffParser struct {
	opts           Options
	s              lineScanner
	skip           bool // the current file is not scanned
	remOld, remNew int  // lines left in the current hunk
	newLine        int  // number of the next added line in the new file
	inAdded        bool // the current output line is an added line
}

func (p *diffParser) parse(ctx context.Context, r io.Reader) error {
	lr := newLineReader(r)
	p.skip = true
	for i := 0; ; i++ {
		if i%4096 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		piece, first, last, err := lr.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		line := string(piece)
		if !first {
			// The rest of a long line.
			if p.inAdded && !p.skip {
				p.s.scan(p.newLine-1, line, false, last)
			}
			continue
		}
		p.inAdded = false
		switch {
		case p.remOld > 0 && p.remNew > 0 && strings.HasPrefix(line, " "):
			// A context line, in case git shows some after all.
			p.remOld--
			p.remNew--
			p.newLine++
		case p.remOld > 0 && strings.HasPrefix(line, "-"):
			p.remOld--
		case p.remNew > 0 && strings.HasPrefix(line, "+"):
			p.remNew--
			p.newLine++
			p.inAdded = true
			if !p.skip {
				p.s.scan(p.newLine-1, line[1:], true, last)
			}
		case strings.HasPrefix(line, `\`):
			// "\ No newline at end of file"
		default:
			p.remOld, p.remNew = 0, 0
			p.header(line)
		}
	}
	p.s.flush()
	return nil
}

// header handles a line outside a hunk: a commit, a file name or the start of
// a hunk. Anything else, such as "index" lines, is ignored.
func (p *diffParser) header(line string) {
	switch {
	case strings.HasPrefix(line, "commit "):
		if m := commitLine.FindStringSubmatch(line); m != nil {
			p.s.flush()
			p.s.commit, p.s.file, p.skip = m[1], "", true
		}
	case strings.HasPrefix(line, "diff --git "):
		p.s.flush()
		p.skip = true
	case strings.HasPrefix(line, "+++ "):
		p.s.flush()
		file := diffPath(line[len("+++ "):])
		p.skip = file == "" || p.opts.skipPath(file) || binaryExtensions[strings.ToLower(path.Ext(file))]
		p.s.file = cleanPath(file)
	case strings.HasPrefix(line, "@@ "):
		p.s.flush()
		m := hunkHeader.FindStringSubmatch(line)
		if m == nil {
			return
		}
		p.remOld, p.remNew = hunkCount(m[2]), hunkCount(m[4])
		p.newLine, _ = strconv.Atoi(m[3])
	}
}

// hunkCount reads a line count from a hunk header, where a missing count
// means one line.
func hunkCount(s string) int {
	if s == "" {
		return 1
	}
	n, _ := strconv.Atoi(s)
	return n
}

// diffPath turns the name on a "+++ " line into a path. Git adds a tab after
// names that contain spaces, and quotes names with unusual characters.
func diffPath(s string) string {
	s = strings.TrimSuffix(s, "\t")
	if s == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		u, err := strconv.Unquote(s)
		if err != nil {
			return ""
		}
		s = u
	}
	return strings.TrimPrefix(s, "b/")
}

// gitEnv is the environment git runs with: the few variables it needs, and
// settings that stop it from fetching missing objects or asking for input.
func gitEnv() []string {
	env := []string{
		"GIT_ALLOW_PROTOCOL=none", // no transport at all, so no fetch can run a program
		"GIT_NO_LAZY_FETCH=1",     // git 2.44 and later: never fetch missing objects
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		"GIT_OPTIONAL_LOCKS=0",
	}
	for _, name := range gitKeepVars {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// checkTopLevel makes sure repo is the top of a repository rather than a
// directory inside one, whose history would include other projects under
// misleading names.
func checkTopLevel(ctx context.Context, git, repo string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, git, append(append(slices.Clone(gitSafety), "-C", repo, "rev-parse"), args...)...)
		cmd.Env = gitEnv()
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	bare, err := run("--is-bare-repository")
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("leaks: %s is not a Git repository", repo)
	}
	query := "--show-toplevel"
	if bare == "true" {
		query = "--absolute-git-dir"
	}
	top, err := run(query)
	if err != nil {
		return fmt.Errorf("leaks: %s is not a Git repository", repo)
	}
	want, err1 := filepath.EvalSymlinks(repo)
	got, err2 := filepath.EvalSymlinks(top)
	if err1 != nil || err2 != nil || filepath.Clean(want) != filepath.Clean(got) {
		return fmt.Errorf("leaks: %s is inside the Git repository %s; scan the repository's top directory for its history", repo, top)
	}
	return nil
}

// limitedReader fails once more than limit bytes have been read.
type limitedReader struct {
	r        io.Reader
	n, limit int64
}

func (l *limitedReader) Read(b []byte) (int, error) {
	if l.n > l.limit {
		return 0, errTooMuchOutput
	}
	n, err := l.r.Read(b)
	l.n += int64(n)
	return n, err
}

// cappedBuffer keeps the first max bytes written to it and drops the rest.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(b []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(b[:min(len(b), room)])
	}
	return len(b), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// Merge adds to the leaks found in the working tree those found only in the
// Git history. A secret counts once per file, by its fingerprint.
func Merge(tree, hist []Leak) []Leak {
	seen := map[string]bool{}
	for _, l := range tree {
		seen[l.Fingerprint+"|"+l.File] = true
	}
	out := slices.Clone(tree)
	for _, l := range hist {
		if !seen[l.Fingerprint+"|"+l.File] {
			seen[l.Fingerprint+"|"+l.File] = true
			out = append(out, l)
		}
	}
	return out
}
