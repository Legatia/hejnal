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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
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
}

var defaultSkipDirs = []string{".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

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

// placeholderWords mark values that are examples rather than real secrets.
// "00000000" stands for a run of 8 zeros.
var placeholderWords = []string{"example", "sample", "dummy", "fake", "test", "xxxx", "00000000", "your_", "changeme"}

// placeholderShapes match template syntax: <name>, ${NAME} and {{ name }}.
var placeholderShapes = regexp.MustCompile(`<[^<>]*>|\$\{[^{}]*\}|\{\{.*?\}\}`)

// trivialValues are words people write where a password goes in examples.
var trivialValues = []string{"password", "passwd", "pass", "pwd", "secret", "token"}

// knownExamples are credentials published in vendor documentation. The
// Azure Storage emulator (Azurite) key is listed by fingerprint, so that this
// file does not itself look like it leaks an Azure key.
var knownExamples = map[string]bool{
	"AKIA" + "IOSFODNN7EXAMPLE": true, // AWS documentation
	"0011cc25eb432071":          true, // Azurite's well-known account key
}

// placeholder reports whether a matched secret is an example value.
func placeholder(secret string) bool {
	if knownExamples[secret] || knownExamples[fingerprint(secret)] {
		return true
	}
	lower := strings.ToLower(secret)
	for _, w := range placeholderWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return slices.Contains(trivialValues, lower) || placeholderShapes.MatchString(secret)
}

// fingerprint is the first 16 hex characters of the secret's SHA-256 hash.
func fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

// redact shortens a secret to a safe form. It shows the rule's known prefix
// plus 2 characters, or otherwise at most the first 4 characters (fewer for
// short secrets), then the length. It never shows more than half the secret.
func redact(secret string, prefixes []string) string {
	n := utf8.RuneCountInString(secret)
	show := min(4, n/4)
	for _, p := range prefixes {
		if strings.HasPrefix(secret, p) {
			show = utf8.RuneCountInString(p) + 2
			break
		}
	}
	show = min(show, n/2)
	return fmt.Sprintf("%s… (%d chars)", string([]rune(secret)[:show]), n)
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
