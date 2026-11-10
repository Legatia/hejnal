package iac

import (
	"strconv"
	"strings"
	"unicode"
)

// Block is a top-level Terraform block, such as resource "aws_s3_bucket"
// "logs" { ... }.
type Block struct {
	Type   string
	Labels []string
	Line   int
	// Body holds attributes, with literal values or Unknown, and nested
	// blocks as lists of maps under their type.
	Body map[string]any
}

type tokKind int

const (
	tEOF tokKind = iota
	tNewline
	tIdent
	tString
	tNumber
	tPunct
	tUnknown // a string with interpolation, or something unreadable
)

type token struct {
	kind tokKind
	text string
	line int
}

// lexHCL splits Terraform source into tokens.
func lexHCL(src string) []token {
	var out []token
	line := 1
	i := 0
	emit := func(k tokKind, s string) { out = append(out, token{k, s, line}) }
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			emit(tNewline, "\n")
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#' || c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				i = len(src)
				break
			}
			line += strings.Count(src[i:i+2+end], "\n")
			i += end + 4
		case c == '"':
			start, startLine := i, line
			i++
			depth := 0
			interp := false
			for i < len(src) {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == '\n' {
					line++
				}
				if depth == 0 && src[i] == '"' {
					break
				}
				if (src[i] == '$' || src[i] == '%') && i+1 < len(src) && src[i+1] == '{' && (i == 0 || src[i-1] != src[i]) {
					interp = true
					depth++
					i += 2
					continue
				}
				if depth > 0 && src[i] == '}' {
					depth--
				}
				i++
			}
			raw := src[start:min(i+1, len(src))]
			i++
			if interp {
				out = append(out, token{tUnknown, raw, startLine})
				continue
			}
			s, err := strconv.Unquote(raw)
			if err != nil {
				s = strings.Trim(raw, `"`)
			}
			out = append(out, token{tString, s, startLine})
		case c == '<' && strings.HasPrefix(src[i:], "<<"):
			j := i + 2
			if j < len(src) && src[j] == '-' {
				j++
			}
			nl := strings.IndexByte(src[j:], '\n')
			if nl < 0 {
				i = len(src)
				break
			}
			marker := strings.TrimSpace(src[j : j+nl])
			startLine := line
			body := []string{}
			k := j + nl + 1
			line++
			for k < len(src) {
				e := strings.IndexByte(src[k:], '\n')
				var l string
				if e < 0 {
					l, e = src[k:], len(src)-k
				} else {
					l = src[k : k+e]
				}
				k += e + 1
				line++
				if strings.TrimSpace(l) == marker {
					break
				}
				body = append(body, l)
			}
			i = k
			text := strings.Join(body, "\n")
			if strings.Contains(text, "${") {
				out = append(out, token{tUnknown, text, startLine})
			} else {
				out = append(out, token{tString, text, startLine})
			}
			line--
			emit(tNewline, "\n")
			line++
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.' || src[j] == 'e' || src[j] == 'E') {
				j++
			}
			emit(tNumber, src[i:j])
			i = j
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(src) && (unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j])) || src[j] == '_' || src[j] == '-') {
				j++
			}
			emit(tIdent, src[i:j])
			i = j
		default:
			emit(tPunct, string(c))
			i++
		}
	}
	emit(tEOF, "")
	return out
}

type hclParser struct {
	toks []token
	i    int
}

func (p *hclParser) peek() token { return p.toks[p.i] }
func (p *hclParser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}
func (p *hclParser) skipNewlines() {
	for p.peek().kind == tNewline {
		p.i++
	}
}

// parseHCL reads the top-level blocks of a Terraform file. It never fails:
// what it cannot read becomes Unknown or is skipped.
func parseHCL(src string) []Block {
	p := &hclParser{toks: lexHCL(src)}
	var out []Block
	for {
		p.skipNewlines()
		t := p.peek()
		if t.kind == tEOF {
			return out
		}
		if t.kind != tIdent {
			p.next()
			continue
		}
		name, labels, body, isBlock := p.item(0)
		if isBlock {
			out = append(out, Block{Type: name, Labels: labels, Line: t.line, Body: body})
		}
	}
}

// item reads an attribute or a block at the current identifier.
func (p *hclParser) item(depth int) (name string, labels []string, body map[string]any, isBlock bool) {
	t := p.next()
	name = t.text
	switch nt := p.peek(); {
	case nt.kind == tPunct && nt.text == "=":
		p.next()
		v := p.expr(depth)
		return name, nil, map[string]any{"=": v}, false
	default:
		for {
			nt = p.peek()
			switch {
			case nt.kind == tString || nt.kind == tIdent:
				labels = append(labels, nt.text)
				p.next()
				continue
			case nt.kind == tPunct && nt.text == "{":
				p.next()
				return name, labels, p.body(depth+1, t.line), true
			}
			break
		}
		// Not something Hejnal reads: skip the line.
		for p.peek().kind != tNewline && p.peek().kind != tEOF {
			p.next()
		}
		return name, nil, nil, false
	}
}

func (p *hclParser) body(depth, line int) map[string]any {
	m := map[string]any{LineKey: line}
	if depth > 64 {
		p.skipTo("}")
		return m
	}
	for {
		p.skipNewlines()
		t := p.peek()
		switch {
		case t.kind == tEOF:
			return m
		case t.kind == tPunct && t.text == "}":
			p.next()
			return m
		case t.kind != tIdent && t.kind != tString:
			p.next()
			continue
		}
		name, _, b, isBlock := p.item(depth)
		if isBlock {
			list, _ := m[name].([]any)
			m[name] = append(list, b)
		} else if b != nil {
			m[name] = b["="]
		}
	}
}

func (p *hclParser) skipTo(closing string) {
	depth := 0
	for {
		t := p.next()
		if t.kind == tEOF {
			return
		}
		if t.kind == tPunct && (t.text == "{" || t.text == "[" || t.text == "(") {
			depth++
		}
		if t.kind == tPunct && (t.text == "}" || t.text == "]" || t.text == ")") {
			if depth == 0 && t.text == closing {
				return
			}
			depth--
		}
	}
}

// expr reads an expression: a literal, or a list or object of them. Any
// operator, reference or function call makes it Unknown.
func (p *hclParser) expr(depth int) any {
	v := p.primary(depth)
	// Anything after the value but before the end makes it computed.
	t := p.peek()
	if t.kind == tNewline || t.kind == tEOF || t.kind == tPunct && (t.text == "," || t.text == "]" || t.text == "}" || t.text == ")") {
		return v
	}
	p.skipExpr()
	return Unknown{}
}

// skipExpr skips to the end of the current expression.
func (p *hclParser) skipExpr() {
	depth := 0
	for {
		t := p.peek()
		switch {
		case t.kind == tEOF:
			return
		case t.kind == tNewline && depth == 0:
			return
		case t.kind == tPunct && (t.text == "{" || t.text == "[" || t.text == "("):
			depth++
		case t.kind == tPunct && (t.text == "}" || t.text == "]" || t.text == ")" || t.text == ","):
			if depth == 0 {
				return
			}
			if t.text != "," {
				depth--
			}
		}
		p.next()
	}
}

func (p *hclParser) primary(depth int) any {
	if depth > 64 {
		p.skipExpr()
		return Unknown{}
	}
	t := p.peek()
	switch {
	case t.kind == tString:
		p.next()
		return t.text
	case t.kind == tNumber:
		p.next()
		if f, err := strconv.ParseFloat(t.text, 64); err == nil {
			return f
		}
		return Unknown{}
	case t.kind == tIdent && (t.text == "true" || t.text == "false"):
		p.next()
		if nt := p.peek(); nt.kind == tPunct && nt.text != "," && nt.text != "]" && nt.text != "}" && nt.text != ")" {
			return Unknown{}
		}
		return t.text == "true"
	case t.kind == tIdent && t.text == "null":
		p.next()
		return nil
	case t.kind == tPunct && t.text == "[":
		p.next()
		var list []any
		for {
			p.skipNewlines()
			nt := p.peek()
			if nt.kind == tEOF {
				return list
			}
			if nt.kind == tPunct && nt.text == "]" {
				p.next()
				return list
			}
			if nt.kind == tIdent && nt.text == "for" {
				p.skipTo("]")
				return Unknown{}
			}
			list = append(list, p.expr(depth+1))
			p.skipNewlines()
			if nt := p.peek(); nt.kind == tPunct && nt.text == "," {
				p.next()
			}
		}
	case t.kind == tPunct && t.text == "{":
		p.next()
		m := map[string]any{LineKey: t.line}
		for {
			p.skipNewlines()
			nt := p.peek()
			if nt.kind == tEOF {
				return m
			}
			if nt.kind == tPunct && nt.text == "}" {
				p.next()
				return m
			}
			if nt.kind == tIdent && nt.text == "for" {
				p.skipTo("}")
				return Unknown{}
			}
			key := p.next()
			if sep := p.peek(); sep.kind == tPunct && (sep.text == "=" || sep.text == ":") {
				p.next()
				m[key.text] = p.expr(depth + 1)
			} else {
				p.skipExpr()
			}
			p.skipNewlines()
			if nt := p.peek(); nt.kind == tPunct && nt.text == "," {
				p.next()
			}
		}
	}
	start := p.i
	p.skipExpr()
	if p.i == start {
		p.next() // a stray closing bracket: step over it
	}
	return Unknown{}
}
