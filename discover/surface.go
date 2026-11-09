package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/leaks"
)

// Checks on what a web service's front page already shows, and on a
// domain's DNS records. None of them sends a request beyond those discovery
// makes anyway.

// Exposure kinds found from the front page.
const (
	ExposureTakeover      = "takeover"
	ExposureBucketListing = "bucket-listing"
	ExposureDirListing    = "directory-listing"
	ExposureNonProduction = "non-production"
)

// DNSRecords is what a resolver offers besides addresses. The system
// resolver has it; a resolver without it skips the checks that need it.
type DNSRecords interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// takeoverService is a hosting service that answers in a known way for a
// name pointed at it when nothing is set up there, so anyone with an
// account could set it up and serve pages under the name.
type takeoverService struct {
	name string
	// cname matches the name the host points to, and addrs the addresses
	// it resolves to, for services reached without a CNAME.
	cname *regexp.Regexp
	addrs []netip.Prefix
	body  *regexp.Regexp
}

// takeoverServices lists only services where claiming a dangling name is
// known to work and the answer is unmistakable; services that verify
// ownership, or whose error pages are ambiguous, are left out. So are
// Heroku's herokudns.com and herokussl.com targets: Heroku makes up a new
// random one for every custom domain, so nobody can get the one a name
// still points to.
var takeoverServices = []takeoverService{
	{name: "GitHub Pages", cname: regexp.MustCompile(`(?i)\.github\.io\.?$`),
		addrs: []netip.Prefix{netip.MustParsePrefix("185.199.108.0/22")},
		body:  regexp.MustCompile(`There isn't a GitHub Pages site here\.`)},
	{name: "Heroku", cname: regexp.MustCompile(`(?i)\.herokuapp\.com\.?$`),
		body: regexp.MustCompile(`(?i)<title>No such app</title>|herokucdn\.com/error-pages/no-such-app\.html`)},
	{name: "Amazon S3", cname: regexp.MustCompile(`(?i)(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com\.?$`),
		body: regexp.MustCompile(`<Code>NoSuchBucket</Code>`)},
	{name: "Surge.sh", cname: regexp.MustCompile(`(?i)(^|\.)surge\.sh\.?$`),
		body: regexp.MustCompile(`project not found`)},
	{name: "Pantheon", cname: regexp.MustCompile(`(?i)\.pantheonsite\.io\.?$`),
		body: regexp.MustCompile(`The gods are wise, but do not know of the site which you seek\.`)},
	{name: "Help Scout Docs", cname: regexp.MustCompile(`(?i)\.helpscoutdocs\.com\.?$`),
		body: regexp.MustCompile(`No settings were found for this company:`)},
	{name: "ReadMe", cname: regexp.MustCompile(`(?i)\.readme\.io\.?$`),
		body: regexp.MustCompile(`The creators of this project are still working on making everything perfect!`)},
	{name: "Strikingly", cname: regexp.MustCompile(`(?i)\.s\.strikinglydns\.com\.?$`),
		body: regexp.MustCompile(`But if you're looking to build your own website,`)},
	{name: "WordPress.com", cname: regexp.MustCompile(`(?i)\.wordpress\.com\.?$`),
		body: regexp.MustCompile(`Do you want to register <em>[^<]*\.wordpress\.com</em>\?`)},
	{name: "Bitbucket", cname: regexp.MustCompile(`(?i)\.bitbucket\.io\.?$`),
		body: regexp.MustCompile(`Repository not found`)},
}

// takeover reports the service an unclaimed name points to.
func takeover(cname string, addrs []netip.Addr, body string) (string, bool) {
	for _, s := range takeoverServices {
		pointed := cname != "" && s.cname.MatchString(cname)
		for _, p := range s.addrs {
			pointed = pointed || slices.ContainsFunc(addrs, p.Contains)
		}
		if pointed && s.body.MatchString(body) {
			return s.name, true
		}
	}
	return "", false
}

var (
	s3ListingRE    = regexp.MustCompile(`<ListBucketResult xmlns="http://(?:doc\.)?s3\.amazonaws\.com/doc/2006-03-01/?">`)
	azureListingRE = regexp.MustCompile(`<EnumerationResults[^>]+ContainerName=`)
	listingKeyRE   = regexp.MustCompile(`<(?:Key|Name)>`)
	dirIndexRE     = regexp.MustCompile(`(?i)<title>\s*Index of /[^<]*</title>[\s\S]*?<h1>\s*Index of /`)
	dirEntryRE     = regexp.MustCompile(`(?i)<a href="[^"?/][^"]*"`)
	loginTitleRE   = regexp.MustCompile(`(?i)\b(log ?in|sign ?in|password|authenticat)`)
)

// listing reports a storage bucket or a web server that lists its files.
// Evidence counts entries without naming them.
func listing(body string) (kind, evidence string) {
	switch {
	case s3ListingRE.MatchString(body), azureListingRE.MatchString(body):
		return ExposureBucketListing, fmt.Sprintf("a storage bucket lists its files to anyone (%d or more entries seen; names not stored)", len(listingKeyRE.FindAllStringIndex(body, -1)))
	case dirIndexRE.MatchString(body):
		return ExposureDirListing, fmt.Sprintf("the web server lists the folder's files (%d or more entries seen; names not stored)", max(len(dirEntryRE.FindAllStringIndex(body, -1))-1, 0))
	}
	return "", ""
}

// nonProduction holds the first labels that name a staging, development or
// test copy of a site.
var nonProduction = map[string]bool{
	"staging": true, "stage": true, "stg": true, "dev": true, "develop": true, "development": true,
	"test": true, "testing": true, "qa": true, "uat": true, "preview": true, "sandbox": true, "preprod": true,
}

// nonProductionName reports whether host's first label names a staging or
// test copy, such as "staging", "dev2" or "api-staging".
func nonProductionName(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	first, _, _ := strings.Cut(host, ".")
	for _, part := range strings.Split(first, "-") {
		if nonProduction[strings.TrimRight(part, "0123456789")] {
			return true
		}
	}
	return false
}

// productionNames returns the names a staging or test copy at host is
// likely a copy of: the parent name, its www name, and the name without
// the staging part, so "api-staging.example.com" gives "example.com",
// "www.example.com" and "api.example.com".
func productionNames(host string) []string {
	first, parent, _ := strings.Cut(host, ".")
	if !strings.Contains(parent, ".") {
		return nil
	}
	out := []string{parent, "www." + parent}
	var keep []string
	for _, part := range strings.Split(first, "-") {
		if !nonProduction[strings.TrimRight(part, "0123456789")] {
			keep = append(keep, part)
		}
	}
	if len(keep) > 0 {
		out = append(out, strings.Join(keep, "-")+"."+parent)
	}
	return out
}

var (
	// noindexRE matches a robots meta tag that keeps search engines away,
	// as preview and staging deployments usually have.
	noindexRE = regexp.MustCompile(`(?i)<meta\b[^>]*\bname\s*=\s*["']?(?:robots|googlebot)\b[^>]*\bcontent\s*=\s*["'][^"']*\bnoindex|<meta\b[^>]*\bcontent\s*=\s*["'][^"']*\bnoindex[^>]*\bname\s*=\s*["']?(?:robots|googlebot)\b`)
	// testTitleRE matches a page title that calls the site a copy for
	// testing: "Acme (staging)", "[UAT] Acme", "Acme test environment".
	// Words that also name public sites, such as "dev" for a developer
	// portal, "QA" for questions and answers or "sandbox" for an API
	// sandbox, count only in brackets.
	testTitleRE = regexp.MustCompile(`(?i)\bstaging\b|\bpre-?prod(?:uction)?\b|\buat\b|\b(?:test|testing|dev|development|qa)\s+(?:environment|server|instance|system|site)\b|[\[(]\s*(?:dev|test|testing|qa|stage|stg|preview|sandbox)\s*[\])]`)
	// stagingTextRE matches a page that says it is a staging copy.
	stagingTextRE = regexp.MustCompile(`(?i)\b(?:staging|pre-?production)\s+(?:environment|server|site|system|instance)\b`)
	passwordRE    = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?password\b`)
	hiddenRE      = regexp.MustCompile(`(?is)<(script|style|noscript|template|head)\b.*?</(?:script|style|noscript|template|head)\s*>`)
	tagRE         = regexp.MustCompile(`(?s)<[^>]*>`)
)

// shell reports whether a page shows next to no text of its own, as a
// single-page application's start page does before its scripts run. Such a
// page looks the same whether or not the application then asks for a login.
func shell(body string) bool {
	text := tagRE.ReplaceAllString(hiddenRE.ReplaceAllString(body, " "), " ")
	letters := 0
	for _, c := range html.UnescapeString(text) {
		if unicode.IsLetter(c) {
			letters++
		}
	}
	return letters < 40
}

// nonProductionSign returns what on a front page, besides the name, marks
// a staging or test copy. ok is false for a page that cannot show it: a
// login, or a page without text of its own, since Hejnal cannot see past a
// login. A page with no sign may still show the live site's page.
func nonProductionSign(header http.Header, title, body string) (sign string, ok bool) {
	if loginTitleRE.MatchString(title) || passwordRE.MatchString(body) || shell(body) {
		return "", false
	}
	switch {
	case strings.Contains(strings.ToLower(strings.Join(header.Values("X-Robots-Tag"), ",")), "noindex"), noindexRE.MatchString(body):
		return "asks search engines not to index it", true
	case testTitleRE.MatchString(title):
		return fmt.Sprintf("its title %q names it a test copy", truncate(title, 80)), true
	case stagingTextRE.MatchString(tagRE.ReplaceAllString(hiddenRE.ReplaceAllString(body, " "), " ")):
		return "the page calls itself a staging site", true
	}
	return "", true
}

// surface adds the exposures the front page shows. svc is the service's
// answer to GET /, header its headers and body its start.
func (r *runner) surface(host string, svc *inventory.Service, header http.Header, body string) {
	cname, addrs := r.records(host)
	if name, ok := takeover(cname, addrs, body); ok {
		where := cname
		if where == "" {
			where = name + "'s addresses"
		}
		svc.Exposures = append(svc.Exposures, inventory.Exposure{Kind: ExposureTakeover, Path: "/",
			Evidence: fmt.Sprintf("points to %s, and %s answers that nothing is set up there", where, name)})
		return
	}
	if svc.Status != http.StatusOK {
		return
	}
	if kind, ev := listing(body); kind != "" {
		svc.Exposures = append(svc.Exposures, inventory.Exposure{Kind: kind, Path: "/", Evidence: ev})
	}
	if !nonProductionName(host) {
		return
	}
	switch sign, ok := nonProductionSign(header, svc.Title, body); {
	case !ok:
	case sign != "":
		svc.Exposures = append(svc.Exposures, nonProductionExposure(host, sign))
	case strings.TrimSpace(svc.Title) != "":
		// Whether it shows the live site's page is known once that site
		// was looked at too.
		r.mu.Lock()
		r.copies = append(r.copies, copyCandidate{host: host, port: svc.Port, title: svc.Title})
		r.mu.Unlock()
	}
}

func nonProductionExposure(host, sign string) inventory.Exposure {
	return inventory.Exposure{Kind: ExposureNonProduction, Path: "/",
		Evidence: fmt.Sprintf("the name %q suggests a staging or test copy; its front page answers without a password and %s", host, sign)}
}

// copyCandidate is a front page on a staging or test name that showed no
// sign of its own, kept to compare with the live site's page.
type copyCandidate struct {
	host  string
	port  int
	title string
}

// markCopies flags the staging or test names that show the same page title
// as the live site they are named after.
func (r *runner) markCopies() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.copies {
		for _, name := range productionNames(c.host) {
			live := r.assets[name]
			if live == nil || !slices.ContainsFunc(live.Services, func(s inventory.Service) bool {
				return s.Status == http.StatusOK && strings.EqualFold(strings.TrimSpace(s.Title), strings.TrimSpace(c.title))
			}) {
				continue
			}
			if a := r.assets[c.host]; a != nil {
				for i, s := range a.Services {
					if s.Port == c.port && !slices.ContainsFunc(s.Exposures, func(x inventory.Exposure) bool { return x.Kind == ExposureNonProduction }) {
						a.Services[i].Exposures = append(a.Services[i].Exposures, nonProductionExposure(c.host, "shows the same page title as "+name))
					}
				}
			}
			break
		}
	}
	r.copies = nil
}

// records returns the name host points to, if any, and the addresses it
// resolved to.
func (r *runner) records(host string) (string, []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cnames[host], r.dns[host].all
}

// recordCNAME looks up the name host points to, for names in the scope.
func (r *runner) recordCNAME(ctx context.Context, host string) {
	recs, ok := r.opts.Resolver.(DNSRecords)
	if !ok {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	lctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	cname, err := recs.LookupCNAME(lctx, host+".")
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	if err != nil || cname == "" || cname == host {
		return
	}
	r.mu.Lock()
	r.cnames[host] = cname
	r.mu.Unlock()
}

// Mail checks: whether anyone can send email that looks as if it came from
// the domain.

// mailAuth reads a domain's mail records. A lookup that fails for another
// reason than the record not existing leaves that part unknown, so a
// timeout is never reported as a missing record.
func (r *runner) mailAuth(ctx context.Context, domain string) (inventory.MailAuth, bool) {
	recs, ok := r.opts.Resolver.(DNSRecords)
	if !ok {
		return inventory.MailAuth{}, false
	}
	m := inventory.MailAuth{Domain: domain}
	lookup := func(f func(context.Context) error) error {
		lctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return f(lctx)
	}
	notFound := func(err error) bool {
		var d *net.DNSError
		return errors.As(err, &d) && d.IsNotFound
	}
	if err := lookup(func(c context.Context) error {
		mx, err := recs.LookupMX(c, domain+".")
		for _, x := range mx[:min(len(mx), 5)] {
			m.MX = append(m.MX, strings.TrimSuffix(strings.ToLower(x.Host), "."))
		}
		return err
	}); err != nil && !notFound(err) {
		m.Errors = append(m.Errors, "MX lookup failed")
	}
	// txt returns the record of a kind at name, and whether the lookup
	// answered.
	txt := func(name, prefix string) (string, bool) {
		var rec string
		err := lookup(func(c context.Context) error {
			txts, err := recs.LookupTXT(c, name+".")
			for _, t := range txts {
				t = strings.TrimSpace(t)
				if len(t) >= len(prefix) && strings.EqualFold(t[:len(prefix)], prefix) &&
					(len(t) == len(prefix) || t[len(prefix)] == ' ' || t[len(prefix)] == ';') {
					rec = clipRecord(t)
					break
				}
			}
			return err
		})
		if err != nil && !notFound(err) {
			m.Errors = append(m.Errors, "TXT lookup of "+name+" failed")
			return "", false
		}
		return rec, true
	}
	m.SPF, m.SPFKnown = txt(domain, "v=spf1")
	m.DMARC, m.DMARCKnown = txt("_dmarc."+domain, "v=DMARC1")
	if m.DMARCKnown && m.DMARC == "" {
		// Receivers fall back to a parent domain's record, so a subdomain
		// without its own is covered by its organisation's.
		for _, parent := range dmarcParents(domain) {
			rec, known := txt("_dmarc."+parent, "v=DMARC1")
			if !known {
				m.DMARCKnown = false
				break
			}
			if rec != "" {
				m.DMARC, m.DMARCDomain = rec, parent
				break
			}
		}
	}
	return m, true
}

// dmarcParents returns the parent domains whose DMARC record applies to
// domain when it has none of its own, nearest first. It walks up the name
// as DMARCbis's tree walk does, rather than consulting a list of public
// suffixes: at most seven labels, and never the top-level domain alone.
// The first record found is the organisation's, or a nearer one that
// covers this part of it.
func dmarcParents(domain string) []string {
	labels := strings.Split(domain, ".")
	start := 1
	if len(labels) >= 8 {
		start = len(labels) - 7
	}
	var out []string
	for i := start; i <= len(labels)-2; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

func clipRecord(s string) string {
	if len(s) > 300 {
		return strings.ToValidUTF8(s[:300], "") + "…"
	}
	return s
}

// Secrets in scripts: keys that only belong on a server, shipped to every
// visitor in the JavaScript the page loads.

// ExposureScriptSecret is a secret in a script the front page loads.
const ExposureScriptSecret = "script-secret"

const (
	// maxScripts and maxScript limit how much JavaScript a service's
	// check reads.
	maxScripts = 8
	maxScript  = 2 << 20
)

var scriptSrcRE = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"'<>\s]+)["']`)

// serverSecrets are the leak rules for keys that are never meant to be in
// a browser. Keys made for browsers, such as Google API keys, and patterns
// that match ordinary minified code are left out.
var serverSecrets = map[string]bool{
	"aws-secret-access-key": true, "github-token": true, "github-fine-grained-token": true,
	"gitlab-token": true, "slack-token": true, "slack-webhook": true, "stripe-live-key": true,
	"google-oauth-client-secret": true, "private-key": true, "npm-token": true, "pypi-token": true,
	"sendgrid-api-key": true, "azure-storage-key": true, "telegram-bot-token": true,
	"openai-api-key": true, "anthropic-api-key": true,
}

// sameOriginScripts returns the paths of the scripts page loads from its
// own host, port and scheme, up to maxScripts.
func sameOriginScripts(page *url.URL, body string) []string {
	var out []string
	for _, m := range scriptSrcRE.FindAllStringSubmatch(body, -1) {
		u, err := page.Parse(html.UnescapeString(m[1]))
		if err != nil || u.Scheme != page.Scheme || !strings.EqualFold(u.Host, page.Host) || u.User != nil {
			continue
		}
		p := u.EscapedPath()
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		if p == "" || slices.Contains(out, p) {
			continue
		}
		out = append(out, p)
		if len(out) == maxScripts {
			break
		}
	}
	return out
}

// noteScripts keeps the front page's scripts for the opt-in checks.
func (r *runner) noteScripts(host string, port int, page *url.URL, body string) {
	if !r.opts.Checks {
		return
	}
	scripts := sameOriginScripts(page, body)
	if len(scripts) == 0 {
		return
	}
	r.mu.Lock()
	r.scripts[fmt.Sprintf("%s|%d", host, port)] = scripts
	r.mu.Unlock()
}

// scriptSecrets reads the scripts the front page loads and reports server
// secrets in them, redacted.
func (w *webClient) scriptSecrets(ctx context.Context, host string, port int, svc *inventory.Service) {
	w.r.mu.Lock()
	scripts := w.r.scripts[fmt.Sprintf("%s|%d", host, port)]
	w.r.mu.Unlock()
	var found []string
	seen := map[string]bool{}
	for _, p := range scripts {
		status, _, body, err := w.getN(ctx, host, port, svc.Scheme, p, maxScript)
		if err != nil || status != http.StatusOK {
			continue
		}
		// Scripts carry libraries' key headers, excerpts and placeholders;
		// only a complete private key counts.
		ls, _ := leaks.ScanReader(p, bytes.NewReader(body), leaks.Options{CompleteKeys: true})
		for _, l := range ls {
			if !serverSecrets[l.RuleID] || seen[l.Fingerprint] {
				continue
			}
			seen[l.Fingerprint] = true
			found = append(found, fmt.Sprintf("%s (%s) in %s", l.Description, l.Redacted, p))
		}
	}
	if len(found) == 0 {
		return
	}
	ev := fmt.Sprintf("%d server secret(s) in scripts every visitor downloads: %s", len(found), strings.Join(found[:min(len(found), 3)], "; "))
	svc.Exposures = append(svc.Exposures, inventory.Exposure{Kind: ExposureScriptSecret, Path: "/", Evidence: clipRecord(ev)})
}
