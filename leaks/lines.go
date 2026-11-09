package leaks

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
)

const (
	// maxLinePiece is the longest piece of a line scanned at once. Longer
	// lines, as in minified files, are scanned in overlapping pieces, so
	// memory use stays bounded.
	maxLinePiece = 1 << 20
	// pieceOverlap is how much of a piece is scanned again at the start of
	// the next one, so a secret cut in two is still seen whole.
	pieceOverlap = 4 << 10

	// minPEMBody is the least key data that counts as a private key. Less is
	// an excerpt in documentation, or code that only names the header.
	minPEMBody   = 40
	maxPEMBody   = 64 << 10
	maxPEMLines  = 2000
	minBase64Run = 16
	// minKeyBytes is the smallest complete key, an Ed25519 key in PKCS #8.
	minKeyBytes = 48
)

// lineReader splits text into lines.
type lineReader struct {
	r    *bufio.Reader
	buf  []byte
	cont bool // the next piece continues a line that was cut
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// next returns the next line without its line ending, or the next piece of a
// long line. first reports whether the piece starts a line, and last whether
// it ends one. The piece is valid until the next call.
func (lr *lineReader) next() (piece []byte, first, last bool, err error) {
	first = !lr.cont
	if lr.cont {
		lr.buf = append(lr.buf[:0], lr.buf[len(lr.buf)-pieceOverlap:]...)
	} else {
		lr.buf = lr.buf[:0]
	}
	for {
		chunk, err := lr.r.ReadSlice('\n')
		lr.buf = append(lr.buf, chunk...)
		switch {
		case err == nil:
			lr.cont = false
			return trimEOL(lr.buf), first, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			if len(lr.buf) >= maxLinePiece {
				lr.cont = true
				return lr.buf, first, false, nil
			}
		case errors.Is(err, io.EOF):
			lr.cont = false
			if first && len(lr.buf) == 0 {
				return nil, false, false, io.EOF
			}
			return trimEOL(lr.buf), first, true, nil
		default:
			return nil, false, false, err
		}
	}
}

func trimEOL(b []byte) []byte {
	return bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
}

// lineScanner applies the rules to the lines of one file at a time.
type lineScanner struct {
	file   string
	commit string
	key    []byte // fingerprint key, or nil for the process key
	leaks  []Leak
	pem    *pemBlock
	// complete reports private keys only as complete blocks
	// (Options.CompleteKeys).
	complete bool
}

// pemBlock collects the key data after a private key header.
type pemBlock struct {
	rule  *rule
	line  int
	body  strings.Builder
	lines int
	// label is the header's name, such as "RSA PRIVATE KEY"; end is the
	// line that closes the block, and ended is set once it was seen.
	label     string
	end       string
	ended     bool
	encrypted bool
	// raw is the key data exactly, for the complete-key check.
	raw strings.Builder
}

var (
	pemField    = regexp.MustCompile(`^(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|MessageID|Subject|Encryption|Public-Lines|Private-Lines|Key-Derivation|Argon2-[A-Za-z]+|Private-MAC):`)
	pemEscapes  = strings.NewReplacer(`\n`, "", `\r`, "")
	pemChecksum = regexp.MustCompile(`^=[0-9A-Za-z+/]{4}$`) // an OpenPGP armor checksum
)

// read scans everything r yields, numbering lines from 1.
func (s *lineScanner) read(r io.Reader) error {
	lr := newLineReader(r)
	n := 0
	for {
		piece, first, last, err := lr.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.flush()
			return err
		}
		if first {
			n++
		}
		s.scan(n, string(piece), first, last)
	}
	s.flush()
	return nil
}

// scan checks line n, or one piece of it when first or last is false.
func (s *lineScanner) scan(n int, text string, first, last bool) {
	if s.pem != nil {
		if first && last {
			if i := s.pem.endAt(text); i >= 0 {
				s.pem.add(text[:i])
				s.endPEM()
				return
			}
			if s.pem.takeLine(text) {
				return
			}
		}
		s.endPEM()
	}
	if strings.Contains(text, AllowMarker) {
		return
	}
	lower := ""
	// examples are values a specific rule found to be placeholders, which
	// the general rules after it then leave alone too.
	var examples []string
	for i := range rules {
		r := &rules[i]
		if len(r.keywords) > 0 {
			if lower == "" {
				lower = strings.ToLower(text)
			}
			if !containsAny(lower, r.keywords) {
				continue
			}
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			if !last && m[1] == len(text) {
				continue // the token may go on; the next piece overlaps this one
			}
			if r.pem {
				// Any of the key header forms; the key data follows it.
				s.startPEM(r, n, pemLabel(text, m), text[m[1]:])
				continue
			}
			lo, hi := m[2*r.group], m[2*r.group+1]
			if lo < 0 {
				continue
			}
			secret := text[lo:hi]
			if slices.Contains(examples, secret) {
				continue
			}
			if placeholder(secret, len(r.prefixes) > 0 || r.random || knownToken(secret)) {
				examples = append(examples, secret)
				continue
			}
			if r.minEntropy > 0 && entropy(secret) < r.minEntropy || r.check != nil && !r.check(text, m) {
				continue
			}
			s.add(r, n, secret)
		}
	}
}

func (s *lineScanner) add(r *rule, n int, secret string) {
	s.leaks = append(s.leaks, Leak{
		RuleID:      r.ID,
		Description: r.Description,
		Severity:    r.Severity,
		File:        s.file,
		Line:        n,
		Commit:      s.commit,
		Redacted:    redact(secret, r.prefixes),
		Fingerprint: fingerprint(s.key, secret),
	})
}

// pemLabel returns the name in a private key header match, such as "RSA
// PRIVATE KEY" or "PuTTY-User-Key-File-3".
func pemLabel(text string, m []int) string {
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 {
			return text[m[2*g]:m[2*g+1]]
		}
	}
	return ""
}

// startPEM begins collecting a private key whose header, named label, is on
// line n. rest is the text after the header, which holds the key when it was
// pasted into one line, for example in a JSON string.
func (s *lineScanner) startPEM(r *rule, n int, label, rest string) {
	s.flush()
	s.pem = &pemBlock{rule: r, line: n, label: label}
	switch {
	case strings.HasPrefix(label, "SSH2 "):
		s.pem.end = "---- END " + label + " ----"
	case !strings.HasPrefix(label, "PuTTY"):
		s.pem.end = "-----END " + label + "-----"
	}
	if i := s.pem.endAt(rest); i >= 0 {
		s.pem.add(rest[:i])
		s.endPEM()
		return
	}
	s.pem.add(rest)
}

// endAt returns where an END line starts in text, or -1, and notes whether
// it is the one that matches the header.
func (p *pemBlock) endAt(text string) int {
	i := strings.Index(text, "-----END ")
	if p.end != "" && strings.HasPrefix(p.end, "---- ") {
		i = strings.Index(text, "---- END ")
	}
	if i >= 0 && p.end != "" && strings.HasPrefix(text[i:], p.end) {
		p.ended = true
	}
	return i
}

// endPEM reports the collected key, if there is enough key data. Placeholder
// words are not checked in key data, where random base64 contains them by
// chance; the entropy check catches filler such as "XXXX…" instead.
func (s *lineScanner) endPEM() {
	p := s.pem
	s.pem = nil
	body := p.body.String()
	if len(body) < minPEMBody || entropy(body) < p.rule.minEntropy {
		return
	}
	if s.complete && !p.complete(p.raw.String()) {
		return
	}
	s.add(p.rule, p.line, body)
}

// complete reports whether a block is a whole key: closed by its own END
// line, with key data that decodes to a key's size and starts the way that
// kind of key does. An excerpt such as "MIIEvQIBADANBg…" decodes to the
// start of a structure that claims more bytes than follow.
func (p *pemBlock) complete(body string) bool {
	if !p.ended {
		return false
	}
	data, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(data) < minKeyBytes {
		return false
	}
	switch {
	case p.encrypted:
		return true // the key data is ciphertext, with no structure to see
	case p.label == "OPENSSH PRIVATE KEY":
		return bytes.HasPrefix(data, []byte("openssh-key-v1\x00"))
	case p.label == "PGP PRIVATE KEY BLOCK":
		return data[0]&0x80 != 0 // an OpenPGP packet header
	case strings.HasPrefix(p.label, "SSH2 "):
		return bytes.HasPrefix(data, []byte{0x3f, 0x6e, 0xe2, 0x6b})
	}
	return derSequence(data)
}

// derSequence reports whether data is exactly one DER SEQUENCE, as PKCS #1,
// PKCS #8 and SEC 1 keys are.
func derSequence(data []byte) bool {
	if len(data) < 2 || data[0] != 0x30 {
		return false
	}
	n, head := int(data[1]), 2
	if n&0x80 != 0 {
		size := n & 0x7f
		if size == 0 || size > 3 || len(data) < 2+size {
			return false
		}
		n, head = 0, 2+size
		for _, b := range data[2:head] {
			n = n<<8 | int(b)
		}
	}
	return head+n == len(data)
}

// flush ends a private key block left open at the end of a file or hunk.
func (s *lineScanner) flush() {
	if s.pem != nil {
		s.endPEM()
	}
}

// add appends the longest run of base64 characters in text, ignoring escaped
// line breaks.
func (p *pemBlock) add(text string) {
	if run := longestBase64(pemEscapes.Replace(text)); len(run) >= minBase64Run {
		p.body.WriteString(run)
		p.raw.WriteString(run)
	}
}

// takeLine adds a line of key data, which may be quoted as in source code. It
// reports false for a line that cannot be key data, which ends the block.
func (p *pemBlock) takeLine(text string) bool {
	if p.body.Len() >= maxPEMBody || p.lines >= maxPEMLines {
		return false
	}
	line := pemEscapes.Replace(text)
	t := strings.Trim(line, " \t\"'`,;+()[]\\")
	if strings.HasPrefix(t, "Proc-Type:") && strings.Contains(t, "ENCRYPTED") {
		p.encrypted = true
	}
	if t != "" && !pemField.MatchString(t) && !pemChecksum.MatchString(t) {
		if len(t) < minBase64Run || len(longestBase64(t)) != len(t) {
			return false
		}
		p.body.WriteString(t)
		p.raw.WriteString(keyLine(line))
	}
	p.lines++
	return true
}

// keyLine is a line of key data without the quotes and string
// concatenation around it. Unlike the body, which stays as it always was so
// fingerprints do not change, it keeps a "+" the base64 data itself starts
// or ends with.
func keyLine(line string) string {
	t := strings.TrimSpace(line)
	quoteOrSpace := func(c byte) bool { return strings.IndexByte(" \t\"'`", c) >= 0 }
	if len(t) > 1 && t[0] == '+' && quoteOrSpace(t[1]) {
		t = t[1:]
	}
	if n := len(t); n > 1 && t[n-1] == '+' && quoteOrSpace(t[n-2]) {
		t = t[:n-1]
	}
	return strings.Trim(t, " \t\"'`,;()[]\\")
}

func longestBase64(s string) string {
	best, start := "", -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isBase64(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start > len(best) {
			best = s[start:i]
		}
		start = -1
	}
	return best
}

func isBase64(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '='
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// tokenPrefixes are the public prefixes of every rule.
var tokenPrefixes = func() []string {
	var out []string
	for _, r := range rules {
		out = append(out, r.prefixes...)
	}
	return out
}()

// knownToken reports whether a value starts like a token one of the rules
// knows, so that general rules judge its placeholder words the same way as
// the token's own rule does.
func knownToken(secret string) bool {
	for _, p := range tokenPrefixes {
		if strings.HasPrefix(secret, p) {
			return true
		}
	}
	return false
}
