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
		if f.TechID == "foreign-host" {
			p.SeeIt, p.Command = seeCert(tr, host, 443)
		} else {
			p.SeeIt, p.Command = seeHTTP(tr, f.URL, "")
		}
	case match.KindTakeover:
		if safeName(host) {
			p.SeeIt, p.Command = tr("proof.see.cname"), "dig +short CNAME '"+host+"'"
		}
	case match.KindEmail:
		if safeName(host) {
			p.SeeIt, p.Command = tr("proof.see.mail"), "dig +short TXT '"+host+"'; dig +short TXT '_dmarc."+host+"'"
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
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !safeName(u.Hostname()) {
		return "", ""
	}
	// Percent-encoding keeps quotes and spaces in a path out of the shell.
	cmd = "curl -sk -D - -o /dev/null '" + strings.NewReplacer("'", "%27", " ", "%20").Replace(u.String()) + "'"
	if look = plain(look); look != "" {
		return tr("proof.see.http.look", u.String(), look), cmd
	}
	return tr("proof.see.http", u.String()), cmd
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
		if p.Command != "" {
			line += " " + mdCode(p.Command)
		}
		fmt.Fprintf(b, "- **%s:** %s\n", tr("label.seeit"), line)
	}
}
