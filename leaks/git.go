package leaks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
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

// gitLocationVars would point git at another repository than the one asked
// for, for example when Hejnal itself runs inside a git hook.
var gitLocationVars = []string{
	"GIT_DIR=", "GIT_WORK_TREE=", "GIT_COMMON_DIR=", "GIT_INDEX_FILE=",
	"GIT_OBJECT_DIRECTORY=", "GIT_ALTERNATE_OBJECT_DIRECTORIES=", "GIT_NAMESPACE=",
}

// ScanGitHistory scans every commit on every branch and tag of the git
// repository at repo, including secrets that later commits removed. It runs
// git log and scans only the lines each commit added. Leak.Commit is the
// commit that added the secret, Leak.File the path in that commit and
// Leak.Line the line number in the file as of that commit. When the same
// secret was added to a file more than once, the oldest commit is reported.
//
// Paths in Options.SkipDirs and lockfiles are skipped. ScanGitHistory needs
// git on the PATH. It stops with an error after 512 MiB of git output, and
// when ctx ends.
func ScanGitHistory(ctx context.Context, repo string, opts Options) ([]Leak, error) {
	opts = opts.withDefaults()
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("leaks: git was not found on the PATH; install git to scan repository history")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// --no-textconv keeps git from running conversion programs, so the scan
	// sees the stored text. Fixed prefixes override diff.noprefix settings.
	cmd := exec.CommandContext(runCtx, git, "-C", repo, "log", "-p", "--all", "--reverse",
		"--no-color", "--no-ext-diff", "--no-textconv", "-U0",
		"--src-prefix=a/", "--dst-prefix=b/", "--format=commit %H")
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
		p.s.file = diffPath(line[len("+++ "):])
		p.skip = p.s.file == "" || p.opts.skipPath(p.s.file)
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

func gitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !slicesHasPrefix(gitLocationVars, kv) {
			env = append(env, kv)
		}
	}
	return env
}

func slicesHasPrefix(prefixes []string, s string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
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
