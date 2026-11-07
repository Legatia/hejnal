// Package fingerprint identifies products from a single, ordinary HTTP
// response: headers, cookies, the page title, generator tags and body markers.
// It never sends payloads or probes for weaknesses.
//
// Rules live in rules.json so the community can add products without touching
// Go code. Every rule names the CISA KEV vendor and product it corresponds to.
package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/Legatia/hejnal/inventory"
)

//go:embed rules.json
var defaultRules []byte

// Rule describes how to recognise one product.
type Rule struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Category  string            `json:"category"`
	Admin     bool              `json:"admin,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Cookies   []string          `json:"cookies,omitempty"`
	Path      string            `json:"path,omitempty"`
	Title     string            `json:"title,omitempty"`
	Generator string            `json:"generator,omitempty"`
	Body      []string          `json:"body,omitempty"`
	// Banners match the greeting a non-web service sends when a client
	// connects, such as "220 mail.example.com ESMTP Exim 4.96".
	Banners  []string      `json:"banners,omitempty"`
	Versions []VersionRule `json:"versions,omitempty"`
	// Packaged marks versions from Linux distribution packages, which get
	// security fixes without a new upstream version number.
	Packaged []SourcePattern `json:"packaged,omitempty"`
	KEV      []KEVPattern    `json:"kev,omitempty"`
	// CPE lists the product's NVD names as vendor:product, used to compare
	// the version seen with NVD's affected version ranges.
	CPE []string `json:"cpe,omitempty"`
	// Editions tell the product's software editions apart by the form of
	// the version, for products whose NVD entries are split by edition,
	// such as Jenkins' LTS and weekly lines.
	Editions []EditionRule `json:"editions,omitempty"`
}

// EditionRule names the NVD software edition of versions that match Regex.
type EditionRule struct {
	Edition string `json:"edition"`
	Regex   string `json:"regex"`
}

// SourcePattern matches a pattern against one part of a response. Source
// is "header:<Name>", "title", "generator", "body" or "banner".
type SourcePattern struct {
	Source string `json:"source"`
	Regex  string `json:"regex"`
}

// VersionRule extracts a version from a response part. Source is one of
// "header:<Name>", "title", "generator", "body" or "banner"; the first capture
// group of Regex is the version.
type VersionRule struct {
	Source string `json:"source"`
	Regex  string `json:"regex"`
}

// KEVPattern maps a rule to CISA KEV entries by vendor and product. Text, when
// set, must also match the entry's name or description; it narrows broad
// entries such as "Multiple Products" to the ones that name this product.
type KEVPattern struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Text    string `json:"text,omitempty"`
}

type headerMatcher struct {
	name string
	re   *regexp.Regexp // nil means "header is present"
}

type versionMatcher struct {
	source string
	header string
	re     *regexp.Regexp
}

type kevMatcher struct {
	vendor, product, text *regexp.Regexp
}

type compiled struct {
	Rule
	editions  []compiledEdition
	headers   []headerMatcher
	cookies   []*regexp.Regexp
	path      *regexp.Regexp
	title     *regexp.Regexp
	generator *regexp.Regexp
	body      []*regexp.Regexp
	banners   []*regexp.Regexp
	versions  []versionMatcher
	packaged  []versionMatcher
	kev       []kevMatcher
}

var cpeNameRE = regexp.MustCompile(`^[a-z0-9_.\-]+:[a-z0-9_.\-]+$`)

var editionNameRE = regexp.MustCompile(`^[a-z0-9_.\-]+$`)

type compiledEdition struct {
	name string
	re   *regexp.Regexp
}

// qualifierRE matches a qualifier written straight after a version, such as
// "-M17", "-rc1" or "-dev". The qualifier is kept with the version: a
// pre-release is compared as one, and an unknown qualifier makes the
// version unusable for version checks rather than mistaken for a release.
var qualifierRE = regexp.MustCompile(`^[-_~+]?[A-Za-z][A-Za-z0-9.]*`)

// maxVersionLen is the longest version kept.
const maxVersionLen = 32

// sourceMatcher compiles a pattern for one response part.
func sourceMatcher(source, regex string, needGroup bool) (versionMatcher, error) {
	re, err := ci(regex)
	if err != nil {
		return versionMatcher{}, err
	}
	if needGroup && re.NumSubexp() < 1 {
		return versionMatcher{}, fmt.Errorf("version regex %q needs a capture group", regex)
	}
	vm := versionMatcher{source: source, re: re}
	if name, ok := strings.CutPrefix(source, "header:"); ok {
		vm.source, vm.header = "header", http.CanonicalHeaderKey(name)
	}
	switch vm.source {
	case "header", "title", "generator", "body", "banner":
	default:
		return versionMatcher{}, fmt.Errorf("unknown source %q", source)
	}
	return vm, nil
}

// Engine holds compiled rules.
type Engine struct {
	rules []*compiled
	byID  map[string]*compiled
}

// Default loads the rules shipped with Hejnal.
func Default() (*Engine, error) { return Load(defaultRules) }

// Load compiles a rules document. All patterns are case-insensitive.
func Load(data []byte) (*Engine, error) {
	var doc struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}
	e := &Engine{byID: map[string]*compiled{}}
	for _, r := range doc.Rules {
		c, err := compile(r)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: rule %q: %w", r.ID, err)
		}
		if _, dup := e.byID[r.ID]; dup {
			return nil, fmt.Errorf("fingerprint: duplicate rule %q", r.ID)
		}
		e.rules = append(e.rules, c)
		e.byID[r.ID] = c
	}
	return e, nil
}

func ci(p string) (*regexp.Regexp, error) { return regexp.Compile("(?i)" + p) }

func compile(r Rule) (*compiled, error) {
	if r.ID == "" || r.Name == "" || r.Category == "" {
		return nil, fmt.Errorf("id, name and category are required")
	}
	c := &compiled{Rule: r}
	var err error
	for name, p := range r.Headers {
		h := headerMatcher{name: http.CanonicalHeaderKey(name)}
		if p != "" {
			if h.re, err = ci(p); err != nil {
				return nil, err
			}
		}
		c.headers = append(c.headers, h)
	}
	for _, p := range r.Cookies {
		re, err := ci(p)
		if err != nil {
			return nil, err
		}
		c.cookies = append(c.cookies, re)
	}
	for _, f := range []struct {
		src string
		dst **regexp.Regexp
	}{{r.Path, &c.path}, {r.Title, &c.title}, {r.Generator, &c.generator}} {
		if f.src == "" {
			continue
		}
		if *f.dst, err = ci(f.src); err != nil {
			return nil, err
		}
	}
	for _, p := range r.Body {
		re, err := ci(p)
		if err != nil {
			return nil, err
		}
		c.body = append(c.body, re)
	}
	for _, p := range r.Banners {
		re, err := ci(p)
		if err != nil {
			return nil, err
		}
		c.banners = append(c.banners, re)
	}
	for _, v := range r.Versions {
		vm, err := sourceMatcher(v.Source, v.Regex, true)
		if err != nil {
			return nil, err
		}
		c.versions = append(c.versions, vm)
	}
	for _, p := range r.Packaged {
		vm, err := sourceMatcher(p.Source, p.Regex, false)
		if err != nil {
			return nil, err
		}
		c.packaged = append(c.packaged, vm)
	}
	for _, name := range r.CPE {
		if !cpeNameRE.MatchString(name) {
			return nil, fmt.Errorf("cpe %q must be vendor:product in lower case", name)
		}
	}
	for _, ed := range r.Editions {
		if !editionNameRE.MatchString(ed.Edition) {
			return nil, fmt.Errorf("edition %q must be lower case", ed.Edition)
		}
		re, err := regexp.Compile(ed.Regex)
		if err != nil {
			return nil, fmt.Errorf("edition %q: %w", ed.Edition, err)
		}
		c.editions = append(c.editions, compiledEdition{name: ed.Edition, re: re})
	}
	for _, k := range r.KEV {
		var m kevMatcher
		if m.vendor, err = ci(k.Vendor); err != nil {
			return nil, err
		}
		if m.product, err = ci(k.Product); err != nil {
			return nil, err
		}
		if k.Text != "" {
			if m.text, err = ci(k.Text); err != nil {
				return nil, err
			}
		}
		c.kev = append(c.kev, m)
	}
	if len(c.headers)+len(c.cookies)+len(c.body)+len(c.banners) == 0 && c.path == nil && c.title == nil && c.generator == nil {
		return nil, fmt.Errorf("rule has no signals")
	}
	return c, nil
}

// Response is the part of an HTTP response the rules look at, or the banner
// of a service that is not a web server.
type Response struct {
	Header      http.Header
	CookieNames []string
	Path        string
	Title       string
	Generators  []string
	Body        string
	// Banner is the greeting of a non-web service. Only banner patterns
	// look at it.
	Banner string
}

// NewBanner prepares a non-web service's greeting for matching.
func NewBanner(banner string) Response {
	return Response{Header: http.Header{}, Banner: banner}
}

var (
	titleRE   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaRE    = regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	nameGenRE = regexp.MustCompile(`(?i)\bname\s*=\s*["']?generator["']?`)
	contentRE = regexp.MustCompile(`(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// NewResponse prepares a response for matching.
func NewResponse(h http.Header, path, body string) Response {
	r := Response{Header: h, Path: path, Body: body}
	for _, c := range h.Values("Set-Cookie") {
		name, _, _ := strings.Cut(c, "=")
		if name = strings.TrimSpace(name); name != "" {
			r.CookieNames = append(r.CookieNames, name)
		}
	}
	if m := titleRE.FindStringSubmatch(body); m != nil {
		r.Title = clean(m[1], 200)
	}
	for _, tag := range metaRE.FindAllString(body, 200) {
		if !nameGenRE.MatchString(tag) {
			continue
		}
		if m := contentRE.FindStringSubmatch(tag); m != nil {
			r.Generators = append(r.Generators, clean(m[1]+m[2], 200))
		}
	}
	return r
}

func clean(s string, max int) string {
	s = strings.Join(strings.Fields(html.UnescapeString(s)), " ")
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// Identify returns the products the response reveals, in rule order.
func (e *Engine) Identify(r Response) []inventory.Technology {
	var out []inventory.Technology
	for _, c := range e.rules {
		ev, ok := c.match(r)
		if !ok {
			continue
		}
		t := inventory.Technology{
			ID:       c.ID,
			Name:     c.Name,
			Version:  c.version(r),
			Category: c.Category,
			// Admin marks a web interface; a greeting on another port is
			// not one, even from a product that has one.
			Admin:    c.Admin && r.Banner == "",
			Evidence: ev,
		}
		if t.Version != "" {
			t.Packaged = c.matchAny(c.packaged, r)
		}
		out = append(out, t)
	}
	return out
}

func (c *compiled) match(r Response) (string, bool) {
	if r.Banner != "" {
		// A greeting is matched by banner patterns only: a pattern meant for
		// web pages could match its empty title or path.
		for _, re := range c.banners {
			if re.MatchString(r.Banner) {
				return "banner " + clean(r.Banner, 120), true
			}
		}
		return "", false
	}
	for _, h := range c.headers {
		for _, v := range r.Header.Values(h.name) {
			if h.re == nil || h.re.MatchString(v) {
				return "header " + h.name + ": " + clean(v, 120), true
			}
		}
	}
	for _, re := range c.cookies {
		for _, n := range r.CookieNames {
			if re.MatchString(n) {
				return "cookie " + n, true
			}
		}
	}
	if c.path != nil && c.path.MatchString(r.Path) {
		return "path " + r.Path, true
	}
	if c.title != nil && c.title.MatchString(r.Title) {
		return "title " + r.Title, true
	}
	if c.generator != nil {
		for _, g := range r.Generators {
			if c.generator.MatchString(g) {
				return "generator " + g, true
			}
		}
	}
	for _, re := range c.body {
		if loc := re.FindStringIndex(r.Body); loc != nil {
			return "body " + clean(r.Body[loc[0]:loc[1]], 120), true
		}
	}
	return "", false
}

func (v versionMatcher) inputs(r Response) []string {
	switch v.source {
	case "header":
		return r.Header.Values(v.header)
	case "title":
		return []string{r.Title}
	case "generator":
		return r.Generators
	case "body":
		return []string{r.Body}
	case "banner":
		return []string{r.Banner}
	}
	return nil
}

func (c *compiled) version(r Response) string {
	for _, v := range c.versions {
		for _, in := range v.inputs(r) {
			m := v.re.FindStringSubmatchIndex(in)
			if m == nil || m[2] < 0 || m[3] <= m[2] {
				continue
			}
			ver := in[m[2]:m[3]]
			ver += qualifierRE.FindString(in[m[3]:])
			// Real versions are short; anything longer is not one, and could
			// carry text a hostile server wants shown.
			if ver = strings.TrimSpace(ver); ver != "" && len(ver) <= maxVersionLen {
				return ver
			}
		}
	}
	return ""
}

func (c *compiled) matchAny(ms []versionMatcher, r Response) bool {
	for _, v := range ms {
		for _, in := range v.inputs(r) {
			if v.re.MatchString(in) {
				return true
			}
		}
	}
	return false
}

// CPEs returns the NVD vendor:product names of rule id.
func (e *Engine) CPEs(id string) []string {
	if c, ok := e.byID[id]; ok {
		return c.CPE
	}
	return nil
}

// Edition returns the NVD software edition of version for rule id, or ""
// when the rule does not tell editions apart or none matches.
func (e *Engine) Edition(id, version string) string {
	c, ok := e.byID[id]
	if !ok {
		return ""
	}
	for _, ed := range c.editions {
		if ed.re.MatchString(version) {
			return ed.name
		}
	}
	return ""
}

// MatchesKEV reports whether a KEV entry belongs to the product identified by
// rule id. text is the entry's name and description.
func (e *Engine) MatchesKEV(id, vendor, product, text string) bool {
	c, ok := e.byID[id]
	if !ok {
		return false
	}
	for _, k := range c.kev {
		if !k.vendor.MatchString(vendor) || !k.product.MatchString(product) {
			continue
		}
		if k.text != nil && !k.text.MatchString(text) {
			continue
		}
		return true
	}
	return false
}

// HasKEV reports whether rule id maps to any KEV entries at all.
func (e *Engine) HasKEV(id string) bool {
	c, ok := e.byID[id]
	return ok && len(c.kev) > 0
}

// Rules returns the loaded rules.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	for i, c := range e.rules {
		out[i] = c.Rule
	}
	return out
}
