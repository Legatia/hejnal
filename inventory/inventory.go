// Package inventory defines the asset inventory Hejnal builds for an
// organisation: hosts, the services they expose and the software behind them.
package inventory

import (
	"regexp"
	"strings"
	"time"
)

// Technology is a product identified on a service.
type Technology struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Category string `json:"category"`
	Admin    bool   `json:"admin,omitempty"`
	// Packaged is set for Linux distribution builds, which get security
	// fixes without a new upstream version number.
	Packaged bool `json:"packaged,omitempty"`
	// Static is set when the pages come from a plain file server, such as
	// a static export, so flaws in the application cannot be reached.
	Static   bool   `json:"static,omitempty"`
	Evidence string `json:"evidence"`
}

// TLSInfo describes the certificate a service presented.
type TLSInfo struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"notAfter"`
	DNSNames []string  `json:"dnsNames,omitempty"`
}

// Service is an open port on a host.
type Service struct {
	Port         int          `json:"port"`
	Scheme       string       `json:"scheme"`
	URL          string       `json:"url,omitempty"`
	FinalURL     string       `json:"finalUrl,omitempty"`
	Status       int          `json:"status,omitempty"`
	Title        string       `json:"title,omitempty"`
	Server       string       `json:"server,omitempty"`
	Banner       string       `json:"banner,omitempty"`
	TLS          *TLSInfo     `json:"tls,omitempty"`
	Technologies []Technology `json:"technologies,omitempty"`
	// Exposures are files found readable by the opt-in checks.
	Exposures []Exposure `json:"exposures,omitempty"`
}

// Exposure is a file that should not be public, found by an opt-in check.
// Evidence describes it without its contents.
type Exposure struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Evidence string `json:"evidence"`
}

// Asset is one host and what it exposes.
type Asset struct {
	Host     string    `json:"host"`
	Source   string    `json:"source"`
	IPs      []string  `json:"ips,omitempty"`
	Services []Service `json:"services,omitempty"`
	Errors   []string  `json:"errors,omitempty"`
}

// Inventory is the result of one discovery run.
type Inventory struct {
	Organization string    `json:"organization"`
	GeneratedAt  time.Time `json:"generatedAt"`
	Assets       []Asset   `json:"assets"`
	// Mail holds the mail records of each domain in the scope.
	Mail []MailAuth `json:"mail,omitempty"`
}

// MailAuth is what a domain's DNS says about who may send its email. SPF
// and DMARC hold the records found; the Known flags say the lookup
// answered, so an empty record is really missing rather than unknown.
type MailAuth struct {
	Domain     string   `json:"domain"`
	MX         []string `json:"mx,omitempty"`
	SPF        string   `json:"spf,omitempty"`
	SPFKnown   bool     `json:"spfKnown,omitempty"`
	DMARC      string   `json:"dmarc,omitempty"`
	DMARCKnown bool     `json:"dmarcKnown,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// Counts summarises an inventory.
func (inv *Inventory) Counts() (assets, services, technologies int) {
	for _, a := range inv.Assets {
		assets++
		for _, s := range a.Services {
			services++
			technologies += len(s.Technologies)
		}
	}
	return
}

var (
	spfAllRE    = regexp.MustCompile(`(?i)(?:^|\s)([-~?+]?)all(?:\s|$)`)
	spfRedirect = regexp.MustCompile(`(?i)(?:^|\s)redirect=`)
	dmarcPolicy = regexp.MustCompile(`(?i)(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)`)
)

// Problems lists what the domain's mail records leave open, as keys:
// spf-missing, spf-weak (an SPF record that lets every server through or
// ends without an "all"), dmarc-missing and dmarc-none (a DMARC policy that
// only watches). Parts whose lookup failed are left out.
func (m MailAuth) Problems() []string {
	var out []string
	if m.SPFKnown {
		switch {
		case m.SPF == "":
			out = append(out, "spf-missing")
		case !spfRedirect.MatchString(m.SPF):
			if a := spfAllRE.FindStringSubmatch(m.SPF); a == nil || a[1] == "+" || a[1] == "?" {
				out = append(out, "spf-weak")
			}
		}
	}
	if m.DMARCKnown {
		switch p := dmarcPolicy.FindStringSubmatch(m.DMARC); {
		case p == nil:
			out = append(out, "dmarc-missing")
		case strings.EqualFold(p[1], "none"):
			out = append(out, "dmarc-none")
		}
	}
	return out
}
