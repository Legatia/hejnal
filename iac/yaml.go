package iac

import (
	"strconv"
	"strings"
)

// Unknown stands for a value the file computes, such as a variable,
// a function call or a CloudFormation !Ref: rules never fire on it.
type Unknown struct{}

// LineKey holds, in every map the readers return, the line it starts on.
const LineKey = "#line"

// yamlLine is one line of a YAML document without its comment.
type yamlLine struct {
	n      int
	indent int
	text   string
}

// parseYAML reads the documents of a YAML stream into maps, slices,
// strings, float64s, bools, nil and Unknown. It covers what Kubernetes
// manifests, Compose files and CloudFormation templates use; anchors,
// aliases and tags read as Unknown.
func parseYAML(data []byte) []any {
	var docs []any
	var cur []yamlLine
	flush := func() {
		if len(cur) > 0 {
			p := &yamlParser{lines: cur}
			if v := p.block(0, cur[0].indent); v != nil {
				docs = append(docs, v)
			}
		}
		cur = nil
	}
	raw := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i := 0; i < len(raw); i++ {
		line := raw[i]
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "...") {
			flush()
			continue
		}
		t := strings.TrimRight(stripComment(line), " \t")
		if strings.TrimSpace(t) == "" {
			continue
		}
		indent := len(t) - len(strings.TrimLeft(t, " "))
		cur = append(cur, yamlLine{n: i + 1, indent: indent, text: strings.TrimSpace(t)})
		// A block scalar's lines are text, not structure.
		if strings.HasSuffix(t, "|") || strings.HasSuffix(t, "|-") || strings.HasSuffix(t, ">") || strings.HasSuffix(t, ">-") || strings.HasSuffix(t, "|+") || strings.HasSuffix(t, ">+") {
			var body []string
			for i+1 < len(raw) {
				next := raw[i+1]
				if strings.TrimSpace(next) != "" && len(next)-len(strings.TrimLeft(next, " ")) <= indent {
					break
				}
				body = append(body, strings.TrimSpace(next))
				i++
			}
			last := &cur[len(cur)-1]
			last.text = strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(last.text, "-"), "+"), "|>"), "|>")
			last.text = strings.TrimRight(last.text, " |>") + " " + strconv.Quote(strings.Join(body, "\n"))
		}
	}
	flush()
	return docs
}

// stripComment removes a # comment that is outside quotes.
func stripComment(s string) string {
	inS, inD := false, false
	for i, r := range s {
		switch {
		case r == '\'' && !inD:
			inS = !inS
		case r == '"' && !inS:
			inD = !inD
		case r == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

type yamlParser struct {
	lines []yamlLine
	i     int
}

// block reads the node starting at the current line, whose lines are
// indented by indent.
func (p *yamlParser) block(depth, indent int) any {
	if p.i >= len(p.lines) || depth > 64 {
		return nil
	}
	l := p.lines[p.i]
	if l.text == "-" || strings.HasPrefix(l.text, "- ") {
		return p.seq(depth, l.indent)
	}
	if _, _, ok := splitKey(l.text); ok {
		return p.mapping(depth, l.indent)
	}
	p.i++
	return scalar(l.text)
}

func (p *yamlParser) seq(depth, indent int) any {
	var out []any
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent || !(l.text == "-" || strings.HasPrefix(l.text, "- ")) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		if rest == "" {
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				out = append(out, p.block(depth+1, p.lines[p.i].indent))
			} else {
				out = append(out, nil)
			}
			continue
		}
		if _, _, ok := splitKey(rest); ok || strings.HasPrefix(rest, "- ") {
			// "- key: value": a mapping whose first line shares the dash.
			p.lines[p.i] = yamlLine{n: l.n, indent: indent + 2, text: rest}
			out = append(out, p.block(depth+1, indent+2))
			continue
		}
		p.i++
		out = append(out, scalar(rest))
	}
	return out
}

func (p *yamlParser) mapping(depth, indent int) any {
	m := map[string]any{LineKey: p.lines[p.i].n}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent {
			break
		}
		k, v, ok := splitKey(l.text)
		if !ok {
			break
		}
		p.i++
		if v != "" {
			m[k] = scalar(v)
			continue
		}
		if p.i < len(p.lines) {
			next := p.lines[p.i]
			// A sequence may sit at its key's own indent.
			if next.indent > indent || next.indent == indent && (next.text == "-" || strings.HasPrefix(next.text, "- ")) {
				m[k] = p.block(depth+1, next.indent)
				continue
			}
		}
		m[k] = nil
	}
	return m
}

// splitKey splits "key: value" outside quotes and flow collections.
func splitKey(s string) (key, value string, ok bool) {
	if s == "" || s[0] == '[' || s[0] == '{' || s[0] == '-' && (len(s) == 1 || s[1] == ' ') {
		return "", "", false
	}
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == ':' && !inS && !inD && (i == len(s)-1 || s[i+1] == ' '):
			return unquoteYAML(strings.TrimSpace(s[:i])), strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func unquoteYAML(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}

// scalar reads an inline value: a quoted or plain string, a number, a
// boolean, null, or a flow collection.
func scalar(s string) any {
	s = strings.TrimSpace(s)
	switch {
	case s == "", s == "~", s == "null", s == "Null", s == "NULL":
		return nil
	case s[0] == '!' || s[0] == '*':
		return Unknown{}
	case s[0] == '&':
		_, rest, _ := strings.Cut(s, " ")
		return scalar(rest)
	case s[0] == '[' || s[0] == '{':
		v, _ := flow(s, 0)
		return v
	case s[0] == '"' || s[0] == '\'':
		return unquoteYAML(s)
	case s == "true" || s == "True" || s == "TRUE":
		return true
	case s == "false" || s == "False" || s == "FALSE":
		return false
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !strings.ContainsAny(s, "xXeE_") {
		return f
	}
	return s
}

// flow reads a [..] or {..} collection written on one line.
func flow(s string, depth int) (any, string) {
	if depth > 32 {
		return Unknown{}, ""
	}
	open := s[0]
	closeCh := byte(']')
	if open == '{' {
		closeCh = '}'
	}
	s = strings.TrimSpace(s[1:])
	var list []any
	m := map[string]any{}
	for s != "" && s[0] != closeCh {
		var item any
		var key string
		if s[0] == '[' || s[0] == '{' {
			item, s = flow(s, depth+1)
		} else {
			end := flowEnd(s, closeCh)
			tok := strings.TrimSpace(s[:end])
			s = s[end:]
			if open == '{' {
				k, v, ok := splitKey(tok + " ")
				if !ok {
					k, v = tok, ""
				}
				key = k
				v = strings.TrimSpace(v)
				if v == "" && s != "" && (s[0] == '[' || s[0] == '{') {
					item, s = flow(s, depth+1)
				} else {
					item = scalar(v)
				}
			} else {
				item = scalar(tok)
			}
		}
		if open == '{' {
			if key != "" {
				m[key] = item
			}
		} else {
			list = append(list, item)
		}
		s = strings.TrimSpace(s)
		s = strings.TrimSpace(strings.TrimPrefix(s, ","))
	}
	if s != "" {
		s = s[1:]
	}
	if open == '{' {
		return m, s
	}
	return list, s
}

// flowEnd finds where a flow item ends: at a comma, the closing bracket,
// or a nested collection after a key.
func flowEnd(s string, closeCh byte) int {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case inS || inD:
		case c == ',' || c == closeCh:
			return i
		case (c == '[' || c == '{') && i > 0 && strings.HasSuffix(strings.TrimSpace(s[:i]), ":"):
			return i
		}
	}
	return len(s)
}
