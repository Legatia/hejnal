// Package leaks finds secrets an organisation has leaked in its code, and
// accounts on its email domains that appear in known data breaches.
//
// The secret scanner looks for API keys, tokens, private keys and passwords
// in files (ScanDir, ScanReader) and in every commit of a git repository
// (ScanGitHistory), using rules compiled into the package. It never stores or
// prints a full secret. Each Leak carries a shortened, redacted form and a
// fingerprint instead, which is enough to find the secret and to recognise it
// in later runs.
//
// The Have I Been Pwned client (HIBP) lists the addresses on a verified
// domain that appear in breaches, and Summarise turns the result into a short
// report.
package leaks

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Severity levels, from most to least urgent.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
)

// DefaultMaxFileSize is the largest file ScanDir reads unless Options sets
// another limit: 2 MiB.
const DefaultMaxFileSize int64 = 2 << 20

// AllowMarker on a line tells the scanner to ignore everything on that line,
// for example in a comment next to a value that only looks like a secret.
const AllowMarker = "hejnal:allow"

// Leak is one secret found in a file or a commit. It never holds the secret
// itself.
//
// Fingerprint is the first 16 hex characters of the secret's SHA-256 hash.
// It recognises the same secret across runs, but a fingerprint of a short or
// common password can be matched by guessing, so treat reports as sensitive.
type Leak struct {
	RuleID      string `json:"ruleId"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	// File is the path relative to the scanned directory or repository,
	// with forward slashes.
	File string `json:"file"`
	Line int    `json:"line"`
	// Commit is the commit that added the secret, for history scans.
	Commit string `json:"commit,omitempty"`
	// Redacted shows the start of the secret and its length, for example
	// "ghp_ab… (40 chars)".
	Redacted    string `json:"redacted"`
	Fingerprint string `json:"fingerprint"`
}

// Options control which files are scanned. The zero value uses the defaults.
type Options struct {
	// SkipDirs are names of directories that are never entered. Nil means
	// DefaultSkipDirs(); an empty, non-nil slice skips nothing. An entry
	// containing a slash, such as "docs/fixtures", is matched against the
	// path relative to the root instead of the directory name.
	SkipDirs []string
	// MaxFileSize is the largest file, in bytes, that is read. Zero or less
	// means DefaultMaxFileSize.
	MaxFileSize int64
	// FingerprintKey makes fingerprints keyed hashes (HMAC-SHA256), so
	// nobody without the key can test guesses of a secret against them.
	// Keep it private, and reuse it to recognise the same secret across
	// scans. Nil uses a random key that lasts as long as the process.
	FingerprintKey []byte
	// Skipped, when set, is told about files that were not scanned because
	// they are too large.
	Skipped func(path string, size int64)
}

var defaultSkipDirs = []string{".git", ".hejnal", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

// lockfiles are generated dependency lists full of hashes that look random.
var lockfiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "go.sum": true,
	"Cargo.lock": true, "poetry.lock": true, "composer.lock": true,
}

// DefaultSkipDirs returns the directories skipped when Options.SkipDirs is
// nil: version control data, dependencies, build output and virtual
// environments.
func DefaultSkipDirs() []string { return slices.Clone(defaultSkipDirs) }

func (o Options) withDefaults() Options {
	if o.SkipDirs == nil {
		o.SkipDirs = defaultSkipDirs
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = DefaultMaxFileSize
	}
	return o
}

// skipDir reports whether a directory with this name and relative path is
// skipped.
func (o Options) skipDir(name, rel string) bool {
	for _, d := range o.SkipDirs {
		if strings.Contains(d, "/") {
			if rel == strings.Trim(d, "/") {
				return true
			}
		} else if name == d {
			return true
		}
	}
	return false
}

// skipPath reports whether a file at this slash-separated relative path is
// skipped, because it is a lockfile or sits in a skipped directory.
func (o Options) skipPath(rel string) bool {
	parts := strings.Split(rel, "/")
	if lockfiles[parts[len(parts)-1]] {
		return true
	}
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] != "" && o.skipDir(parts[i], strings.Join(parts[:i+1], "/")) {
			return true
		}
	}
	return false
}

// Placeholder words mark values that are examples rather than real secrets.
// In tokens, which are random, they count anywhere: "ghp_Sample...". In
// passwords, which people choose, only as a word of their own, such as
// "test-key-1", so "Contest#Winner2024!" and "Latest2024pw" are still
// reported.
var (
	placeholderInToken    = regexp.MustCompile(`(?i)example|sample|dummy|fake|test|changeme|change_me|replace_?me|placeholder`)
	placeholderInPassword = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:example|sample|dummy|fake|test|changeme|change_me|replace_?me|placeholder)(?:[^a-z0-9]|$)`)
)

// placeholderMarks mark examples wherever they appear: runs of x or zeros
// and "your_..." names.
var placeholderMarks = regexp.MustCompile(`(?i)xxxx|00000000|your[_-]`)

// placeholderShapes match template syntax: ${NAME} and {{ name }}, and in
// tokens also <name>. A password must be <name> as a whole to count.
var (
	placeholderShapes        = regexp.MustCompile(`\$\{[^{}]*\}|\{\{.*?\}\}`)
	placeholderAngleToken    = regexp.MustCompile(`<[^<>]*>`)
	placeholderAnglePassword = regexp.MustCompile(`^<[^<>]*>$`)
)

// trivialValues are words people write where a password goes in examples.
var trivialValues = []string{"password", "passwd", "pass", "pwd", "secret", "token"}

// knownExamples are credentials published in vendor documentation. The
// Azure Storage emulator (Azurite) key is listed by fingerprint, so that this
// file does not itself look like it leaks an Azure key.
var knownExamples = map[string]bool{
	"AKIA" + "IOSFODNN7EXAMPLE": true, // AWS documentation
	"0011cc25eb432071":          true, // Azurite's well-known account key
}

// placeholder reports whether a matched secret is an example value. token
// is true for random tokens with a known prefix, and false for values people
// choose, such as passwords.
func placeholder(secret string, token bool) bool {
	if knownExamples[secret] || knownExamples[plainHash(secret)] {
		return true
	}
	if slices.Contains(trivialValues, strings.ToLower(secret)) || placeholderMarks.MatchString(secret) ||
		placeholderShapes.MatchString(secret) {
		return true
	}
	if token {
		return placeholderInToken.MatchString(secret) || placeholderAngleToken.MatchString(secret)
	}
	return placeholderInPassword.MatchString(secret) || placeholderAnglePassword.MatchString(secret)
}

// plainHash is the first 16 hex characters of the SHA-256 hash, used only to
// list known example values without spelling them out.
func plainHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

// processKey keys fingerprints when Options.FingerprintKey is not set.
var processKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("leaks: no randomness: " + err.Error())
	}
	return k
}()

// fingerprint is the first 16 hex characters of the secret's HMAC-SHA256
// under key, or under processKey when key is nil.
func fingerprint(key []byte, secret string) string {
	if key == nil {
		key = processKey
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// redact shortens a secret to a safe form: the rule's known public prefix
// plus 2 characters, then the length, such as "ghp_ab… (40 chars)". Secrets
// without a known prefix, such as passwords, show no characters at all,
// because even a few would make short ones easier to guess. It never shows
// more than half the secret.
func redact(secret string, prefixes []string) string {
	n := utf8.RuneCountInString(secret)
	show := 0
	for _, p := range prefixes {
		if strings.HasPrefix(secret, p) {
			show = utf8.RuneCountInString(p) + 2
			break
		}
	}
	show = min(show, n/2)
	return fmt.Sprintf("%s… (%d chars)", string([]rune(secret)[:show]), n)
}

// cleanPath makes a file name safe to show: control characters, line and
// paragraph separators and direction overrides become "?", and very long
// names are shortened, so a name cannot add lines or hidden text to
// reports, chat messages or an AI assistant's input.
func cleanPath(p string) string {
	const maxLen = 300
	var b strings.Builder
	n := 0
	for _, r := range p {
		if n == maxLen {
			b.WriteString("…")
			break
		}
		switch {
		case unicode.IsControl(r), r == '\u2028', r == '\u2029', r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069', r == '\ufeff', r == utf8.RuneError:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// entropy is the Shannon entropy of s in bits per character. Random strings
// from a 62-character alphabet score close to 6; words and repeats score low.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// finish removes repeats of the same secret in the same file, keeping the
// first one found, and sorts by file, line and rule.
func finish(leaks []Leak) []Leak {
	type key struct{ fingerprint, file string }
	seen := make(map[key]bool, len(leaks))
	out := make([]Leak, 0, len(leaks))
	for _, l := range leaks {
		k := key{l.Fingerprint, l.File}
		if !seen[k] {
			seen[k] = true
			out = append(out, l)
		}
	}
	slices.SortStableFunc(out, func(a, b Leak) int {
		return cmp.Or(strings.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line), strings.Compare(a.RuleID, b.RuleID))
	})
	return out
}
