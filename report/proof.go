package report

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/Legatia/hejnal/match"
)

// Verdicts: how sure Hejnal is that an item is real.
const (
	// VerdictConfirmed means Hejnal saw the problem itself.
	VerdictConfirmed = "confirmed"
	// VerdictLikely means what Hejnal saw points to the problem, but it
	// could not check every step from outside.
	VerdictLikely = "likely"
	// VerdictCheck means something Hejnal cannot see may rule it out.
	VerdictCheck = "check"
)

// ProofStep is one thing Hejnal checked.
type ProofStep struct {
	// OK is set for what Hejnal saw, and unset for what it could not.
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

// Proof says how Hejnal knows an item is real, step by step, and how anyone
// can see it for themselves from outside.
type Proof struct {
	Verdict string      `json:"verdict"`
	Summary string      `json:"summary"`
	Steps   []ProofStep `json:"steps,omitempty"`
	// SeeIt says how to see the problem yourself, without Hejnal, and
	// Command is the command to run for it, if any.
	SeeIt   string `json:"seeIt,omitempty"`
	Command string `json:"command,omitempty"`
}

// ProofOf says how Hejnal knows an item is real, in the given language.
func ProofOf(g match.Group, lang string) Proof {
	return proofOf(newTranslator(lang), g)
}

func proofOf(tr translator, g match.Group) Proof {
	if len(g.Findings) == 0 {
		return Proof{}
	}
	f := g.Findings[0]
	p := Proof{Verdict: VerdictConfirmed}
	step := func(ok bool, key string, args ...any) {
		p.Steps = append(p.Steps, ProofStep{OK: ok, Text: tr(key, args...)})
	}
	host := g.Host
	switch g.Kind {
	case match.KindKEV:
		active := match.Active(g.Findings)
		at := g.URL
		if at == "" {
			at = hostPort(g.Host, g.Port)
		}
		if g.Evidence != "" {
			step(true, "proof.answered", at, g.Technology, plain(g.Evidence))
		} else {
			step(true, "proof.answered.bare", at, g.Technology)
		}
		if g.Version != "" {
			step(true, "proof.version", g.Version)
		} else {
			step(false, "proof.noversion")
		}
		var confirmed []string
		condition, packaged := "", false
		for _, f := range active {
			if f.Confidence == match.ConfidenceVersion {
				confirmed = append(confirmed, f.CVE)
			}
			if f.Condition != "" {
				condition = f.Condition
			}
			packaged = packaged || f.Packaged
		}
		switch {
		case packaged:
			step(false, "proof.packaged")
			p.Verdict = VerdictCheck
		case condition != "":
			step(false, "proof.condition", condition)
			p.Verdict = VerdictCheck
		case len(confirmed) > 0:
			step(true, "proof.inrange", g.Version, strings.Join(firstN(confirmed, 3), ", "))
		case g.Version != "":
			step(false, "proof.norange")
			p.Verdict = VerdictLikely
		default:
			p.Verdict = VerdictLikely
		}
		cisa, enisa := "", false
		for _, f := range active {
			// Findings from before ENISA's list name no list: CISA's.
			fromCISA := slices.Contains(f.ListedBy, match.ListCISA) || len(f.ListedBy) == 0 && f.DateAdded != ""
			if fromCISA && (cisa == "" || f.DateAdded < cisa) {
				cisa = f.DateAdded
			}
			enisa = enisa || slices.Contains(f.ListedBy, match.ListENISA)
		}
		switch {
		case cisa != "" && enisa:
			step(true, "proof.exploited.both", cisa)
		case cisa != "":
			step(true, "proof.exploited.cisa", cisa)
		case enisa:
			step(true, "proof.exploited.enisa")
		default:
			step(true, "proof.exploited")
		}
		p.SeeIt, p.Command = seeHTTP(tr, g.URL, g.Evidence)
	case match.KindAdminExposed:
		p.SeeIt, p.Command = seeHTTP(tr, g.URL, g.Evidence)
	case match.KindExposedFile:
		switch f.TechID {
		case "foreign-host":
			// Hejnal saw the certificate, but whether its names are the
			// owner's, under a domain not in the scope, it cannot see.
			_, names, ok := strings.Cut(f.Evidence, "; it names ")
			if !ok {
				names = f.Evidence
			}
			step(true, "proof.foreign.cert", plain(names))
			step(false, "proof.foreign.owner")
			p.Verdict = VerdictCheck
			p.SeeIt, p.Command = seeCert(tr, host, g.Port)
		case "non-production":
			// A guess from the name, backed by what the page showed.
			_, sign, ok := strings.Cut(f.Evidence, "without a password and ")
			if !ok {
				sign = f.Evidence
			}
			step(true, "proof.nonprod.page", plain(sign))
			step(false, "proof.nonprod.guess")
			p.Verdict = VerdictCheck
			p.SeeIt, p.Command = seeHTTP(tr, f.URL, "")
		case "script-secret":
			step(true, "proof.script.found")
			step(false, "proof.secret.untried")
			p.Verdict = VerdictLikely
			p.SeeIt, p.Command = seeHTTP(tr, f.URL, "")
		default:
			p.SeeIt, p.Command = seeHTTP(tr, f.URL, "")
		}
	case match.KindTakeover:
		// A plain lookup shows the CNAME and the addresses it leads to, so
		// it shows a name found through either.
		if safeName(host) {
			p.SeeIt, p.Command = tr("proof.see.cname"), "dig +short '"+host+"'"
		}
	case match.KindEmail:
		if safeName(host) {
			p.SeeIt, p.Command = tr("proof.see.mail"), "dig +short TXT '"+host+"'; dig +short TXT '_dmarc."+host+"'"
			// A parent domain's DMARC record that applies to this one.
			if _, rest, ok := strings.Cut(f.Evidence, "none of its own; "); ok {
				if parent, _, ok := strings.Cut(rest, "'s applies"); ok && safeName(parent) && net.ParseIP(parent) == nil {
					p.Command += "; dig +short TXT '_dmarc." + parent + "'"
				}
			}
		}
	case match.KindTLSExpired, match.KindTLSExpiring:
		p.SeeIt, p.Command = seeCert(tr, host, g.Port)
	case match.KindSecret:
		step(true, "proof.secret.found", secretPlace(tr, f, false))
		step(false, "proof.secret.untried")
		p.Verdict = VerdictLikely
		p.SeeIt = tr("proof.see.file", secretPlace(tr, f, false))
	case match.KindBreach:
		step(false, "proof.breach.accounts")
		p.SeeIt = tr("proof.see.breach")
	}
	p.Summary = tr("proof.verdict." + p.Verdict)
	return p
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "…")
	}
	return s
}

// safeName reports whether a host name or address can go in a command
// between single quotes as it is.
func safeName(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// seeHTTP says how to see a web page's answer: open it, or ask for it with
// curl, and what to look for.
func seeHTTP(tr translator, raw, look string) (text, cmd string) {
	page, ok := safeURL(raw)
	if !ok {
		return "", ""
	}
	cmd = "curl -sk -D - -o /dev/null '" + page + "'"
	if look = plain(look); look != "" {
		return tr("proof.see.http.look", page, look), cmd
	}
	return tr("proof.see.http", page), cmd
}

// safeURL rebuilds a URL a scanned server may have chosen, such as where it
// redirected to, from its scheme, host, port and path alone, with every
// byte of the path outside letters, digits, "-._~/" and valid %XX escapes
// percent-encoded. The query and fragment are left out. Nothing in the
// result can end the quotes around it in a shell, or a code span in
// Markdown.
func safeURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || !safeName(u.Hostname()) {
		return "", false
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		if strings.Trim(p, "0123456789") != "" {
			return "", false
		}
		host += ":" + p
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString(u.Scheme + "://" + host)
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c == '%' && i+2 < len(path) && isHex(path[i+1]) && isHex(path[i+2]):
			b.WriteString(path[i : i+3])
			i += 2
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~/", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String(), true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// seeCert says how to read the certificate a server shows.
func seeCert(tr translator, host string, port int) (text, cmd string) {
	if !safeName(host) || net.ParseIP(host) != nil {
		return "", ""
	}
	if port == 0 {
		port = 443
	}
	return tr("proof.see.cert"), fmt.Sprintf("openssl s_client -connect '%s:%d' -servername '%s' </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName -enddate", host, port, host)
}

// mdCommand shows a command verbatim as inline code, unlike mdCode, which
// may change it: the code span's fence is longer than any run of backticks
// in the command, so what a reader copies is the command itself. A command
// with a line break is not shown.
func mdCommand(cmd string) string {
	if cmd == "" || strings.ContainsAny(cmd, "\r\n") {
		return ""
	}
	longest, run := 0, 0
	for i := 0; i < len(cmd); i++ {
		if cmd[i] == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(cmd, "`") || strings.HasSuffix(cmd, "`") || strings.HasPrefix(cmd, " ") && strings.HasSuffix(cmd, " ") {
		// Markdown drops one space at each end of a code span.
		cmd = " " + cmd + " "
	}
	return fence + cmd + fence
}

// proofLines writes an item's proof into a fix list.
func proofLines(b *strings.Builder, tr translator, g match.Group) {
	p := proofOf(tr, g)
	if p.Verdict == "" {
		return
	}
	fmt.Fprintf(b, "- **%s:** %s\n", tr("label.howsure"), p.Summary)
	for _, s := range p.Steps {
		mark := "✓"
		if !s.OK {
			mark = "?"
		}
		fmt.Fprintf(b, "  - %s %s\n", mark, mdEscape(s.Text))
	}
	if p.SeeIt != "" {
		line := mdEscape(p.SeeIt)
		if c := mdCommand(p.Command); c != "" {
			line += " " + c
		}
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.seeit"), line)
	}
}
