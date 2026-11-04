package leaks

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"regexp"
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
	leaks  []Leak
	pem    *pemBlock
}

// pemBlock collects the key data after a private key header.
type pemBlock struct {
	rule  *rule
	line  int
	body  strings.Builder
	lines int
}

var (
	pemField   = regexp.MustCompile(`^(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|MessageID):`)
	pemEscapes = strings.NewReplacer(`\n`, "", `\r`, "")
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
			if i := strings.Index(text, "-----END "); i >= 0 {
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
			lo, hi := m[2*r.group], m[2*r.group+1]
			if lo < 0 {
				continue
			}
			if r.pem {
				s.startPEM(r, n, text[m[1]:])
				continue
			}
			secret := text[lo:hi]
			if r.minEntropy > 0 && entropy(secret) < r.minEntropy || placeholder(secret) ||
				r.check != nil && !r.check(text, m) {
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
		Fingerprint: fingerprint(secret),
	})
}

// startPEM begins collecting a private key whose header is on line n. rest is
// the text after the header, which holds the key when it was pasted into one
// line, for example in a JSON string.
func (s *lineScanner) startPEM(r *rule, n int, rest string) {
	s.flush()
	s.pem = &pemBlock{rule: r, line: n}
	if i := strings.Index(rest, "-----END "); i >= 0 {
		s.pem.add(rest[:i])
		s.endPEM()
		return
	}
	s.pem.add(rest)
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
	s.add(p.rule, p.line, body)
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
	}
}

// takeLine adds a line of key data, which may be quoted as in source code. It
// reports false for a line that cannot be key data, which ends the block.
func (p *pemBlock) takeLine(text string) bool {
	if p.body.Len() >= maxPEMBody || p.lines >= maxPEMLines {
		return false
	}
	t := strings.Trim(pemEscapes.Replace(text), " \t\"'`,;+()[]")
	if t != "" && !pemField.MatchString(t) {
		if len(t) < minBase64Run || len(longestBase64(t)) != len(t) {
			return false
		}
		p.body.WriteString(t)
	}
	p.lines++
	return true
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
