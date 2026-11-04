package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/state"
)

const (
	// defaultLimit and maxLimit bound how many findings hejnal_findings
	// returns.
	defaultLimit = 50
	maxLimit     = 500
	// maxHosts is how many hosts hejnal_inventory lists.
	maxHosts = 200
	// maxListed is how many items a summary lists in its text.
	maxListed = 10
)

// tool is one MCP tool.
type tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`

	call func(ctx context.Context, args json.RawMessage) toolResult
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is the result of tools/call. A tool that fails sets IsError and
// explains why in the text, so the assistant can correct itself.
type toolResult struct {
	Content           []content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	IsError           bool      `json:"isError,omitempty"`
}

func textResult(text string) toolResult {
	return toolResult{Content: []content{{Type: "text", Text: text}}}
}

// failure explains why a tool call failed.
func failure(msg string) toolResult {
	r := textResult(sentence(msg))
	r.IsError = true
	return r
}

// sentence turns an error message into a sentence.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[size:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func (s *Server) makeTools() []*tool {
	readOnly := map[string]any{"readOnlyHint": true, "openWorldHint": false}
	lang := map[string]any{
		"type":        "string",
		"enum":        report.Languages,
		"description": "Report language: en (English) or pl (Polish). Default: " + s.lang + ".",
	}
	minSeverity := map[string]any{
		"type":        "string",
		"enum":        []string{"critical", "high", "medium", "low"},
		"description": "Only items at or above this severity: critical (fix now), high (this week), medium (this month) or low (later).",
	}
	tools := []*tool{{
		Name:  "hejnal_summary",
		Title: "Hejnal summary",
		Description: "Summary of the latest Hejnal run: open items by severity, what is new or resolved since the last report, " +
			"and the catalog version and time of the run. Start here. It does not mark anything as reported.",
		InputSchema: objectSchema(nil),
		Annotations: readOnly,
		call:        s.summaryTool,
	}, {
		Name:  "hejnal_fix_list",
		Title: "Fix list",
		Description: "The prioritised fix list from the latest run, in Markdown: what to fix, most urgent first, " +
			"why, what to do and the vendor advisories.",
		InputSchema: objectSchema(map[string]any{"lang": lang, "min_severity": minSeverity}),
		Annotations: readOnly,
		call:        s.fixListTool,
	}, {
		Name:  "hejnal_findings",
		Title: "Findings",
		Description: "Individual findings from the latest run, most urgent first, as text and structured data: " +
			"known exploited flaws (CVEs) in recognised products, certificate problems, exposed admin interfaces and files, " +
			"secrets in source code and accounts in data breaches.",
		InputSchema: objectSchema(map[string]any{
			"min_severity": minSeverity,
			"host":         map[string]any{"type": "string", "description": "Only this host name or IP address."},
			"cve":          map[string]any{"type": "string", "description": "Only this CVE ID, for example CVE-2024-4577."},
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": maxLimit, "default": defaultLimit,
				"description": fmt.Sprintf("How many findings to return, most urgent first: 1 to %d. Default %d.", maxLimit, defaultLimit)},
		}),
		Annotations: readOnly,
		call:        s.findingsTool,
	}, {
		Name:  "hejnal_inventory",
		Title: "Inventory",
		Description: "What Hejnal found in the authorised scope: hosts, the services they expose and the products " +
			"recognised on them, with versions where shown.",
		InputSchema: objectSchema(map[string]any{
			"host": map[string]any{"type": "string", "description": "Only this host name or IP address."},
		}),
		Annotations: readOnly,
		call:        s.inventoryTool,
	}, {
		Name:  "hejnal_nis2_draft",
		Title: "NIS2 early-warning draft",
		Description: "A draft NIS2 Article 23 early warning in Markdown, pre-filled with the systems and flaws from the " +
			"latest run. Use it only when a system was compromised or a service disrupted: a matching flaw alone is not an incident.",
		InputSchema: objectSchema(map[string]any{"lang": lang}),
		Annotations: readOnly,
		call:        s.nis2Tool,
	}}
	if s.allowRuns {
		tools = append(tools, &tool{
			Name:  "hejnal_run",
			Title: "Check now",
			Description: "Checks the systems in the authorised scope again: finds hosts and services, recognises products " +
				"and matches them against CISA's catalog of exploited flaws, then summarises what changed. It contacts the " +
				"organisation's systems over the network and can take minutes. It does not mark anything as reported.",
			InputSchema: objectSchema(nil),
			Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true},
			call:        s.runTool,
		})
	}
	return tools
}

func objectSchema(props map[string]any) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	return map[string]any{"type": "object", "properties": props, "additionalProperties": false}
}

// noArgs is the arguments of tools that take none.
type noArgs struct{}

// decodeArgs decodes a tool's arguments, rejecting unknown ones.
func decodeArgs[T any](raw json.RawMessage) (T, error) {
	var args T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&args); err != nil {
		return args, argError(err, reflect.TypeOf(args))
	}
	return args, nil
}

// argError explains a decoding error in terms of the tool's arguments.
func argError(err error, t reflect.Type) error {
	var names []string
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" {
			names = append(names, name)
		}
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("argument %q must be %s", typeErr.Field, describe(typeErr.Type))
	}
	if name, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		if len(names) == 0 {
			return fmt.Errorf("unknown argument %s: this tool takes no arguments", name)
		}
		return fmt.Errorf("unknown argument %s: use %s", name, strings.Join(names, ", "))
	}
	return fmt.Errorf("invalid arguments: %v", err)
}

func describe(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return "a string"
	case reflect.Int, reflect.Int64:
		return "a whole number"
	}
	return "a " + t.String()
}

func (s *Server) langArg(v string) (string, error) {
	if v == "" {
		return s.lang, nil
	}
	if l := strings.ToLower(strings.TrimSpace(v)); report.ValidLang(l) {
		return l, nil
	}
	return "", fmt.Errorf("unknown language %q: use %s", v, strings.Join(report.Languages, " or "))
}

// loadFindings reads the latest findings, with an error that says what to do
// when there are none.
func (s *Server) loadFindings() (*state.Snapshot, error) {
	if s.broken != nil {
		return nil, s.broken
	}
	snap, err := s.store.LoadFindings()
	switch {
	case errors.Is(err, state.ErrNoFindings):
		return nil, s.notYet(err)
	case err != nil:
		s.logf("mcp: %v", err)
		return nil, fmt.Errorf("could not read Hejnal's findings: %w", err)
	}
	return snap, nil
}

func (s *Server) loadInventory() (*inventory.Inventory, error) {
	if s.broken != nil {
		return nil, s.broken
	}
	inv, err := s.store.LoadInventory()
	switch {
	case errors.Is(err, state.ErrNoInventory):
		return nil, s.notYet(err)
	case err != nil:
		s.logf("mcp: %v", err)
		return nil, fmt.Errorf("could not read Hejnal's inventory: %w", err)
	}
	return inv, nil
}

func (s *Server) notYet(err error) error {
	if s.allowRuns {
		return fmt.Errorf("%w, or call hejnal_run to check the systems now", err)
	}
	return err
}

func (s *Server) summaryTool(_ context.Context, raw json.RawMessage) toolResult {
	if _, err := decodeArgs[noArgs](raw); err != nil {
		return failure(err.Error())
	}
	snap, err := s.loadFindings()
	if err != nil {
		return failure(err.Error())
	}
	ch, err := s.changeEngine.Changes(snap)
	if err != nil {
		s.logf("mcp: comparing with the last report: %v", err)
		return failure("could not compare the findings with the last report: " + err.Error())
	}
	text, sum := summarize(snap, ch)
	return toolResult{Content: []content{{Type: "text", Text: text}}, StructuredContent: sum}
}

type fixListArgs struct {
	Lang        string `json:"lang"`
	MinSeverity string `json:"min_severity"`
}

func (s *Server) fixListTool(_ context.Context, raw json.RawMessage) toolResult {
	a, err := decodeArgs[fixListArgs](raw)
	if err != nil {
		return failure(err.Error())
	}
	lang, err := s.langArg(a.Lang)
	if err != nil {
		return failure(err.Error())
	}
	minSev, err := match.ParseSeverity(a.MinSeverity)
	if err != nil {
		return failure(err.Error())
	}
	snap, err := s.loadFindings()
	if err != nil {
		return failure(err.Error())
	}
	fs, note := snap.Findings, ""
	if minSev != "" {
		// Keep whole items, as the fix list groups them, so each kept item
		// still lists all its flaws.
		var kept []match.Finding
		left := 0
		for _, g := range match.Groups(fs) {
			if g.Severity.Rank() >= minSev.Rank() {
				kept = append(kept, g.Findings...)
			} else {
				left++
			}
		}
		if len(kept) == 0 && left > 0 {
			return textResult(fmt.Sprintf("No items at %s severity or above in the run of %s. %s below it are left out; call hejnal_fix_list without min_severity to see them.",
				minSev, when(snap.GeneratedAt), plural(left, "item")))
		}
		if left > 0 {
			note = fmt.Sprintf("Only items at %s severity or above are shown; %s below it are left out.", minSev, plural(left, "item"))
		}
		fs = kept
	}
	var buf bytes.Buffer
	if err := report.FixList(&buf, fs, engine.Meta(snap, lang)); err != nil {
		return failure("could not write the fix list: " + err.Error())
	}
	res := textResult(buf.String())
	if note != "" {
		res.Content = append(res.Content, content{Type: "text", Text: note})
	}
	return res
}

type findingsArgs struct {
	MinSeverity string `json:"min_severity"`
	Host        string `json:"host"`
	CVE         string `json:"cve"`
	Limit       *int   `json:"limit"`
}

type findingsData struct {
	Organization string          `json:"organization"`
	GeneratedAt  time.Time       `json:"generatedAt"`
	KEVVersion   string          `json:"kevVersion"`
	Total        int             `json:"total"`
	Returned     int             `json:"returned"`
	Findings     []match.Finding `json:"findings"`
}

var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (s *Server) findingsTool(_ context.Context, raw json.RawMessage) toolResult {
	a, err := decodeArgs[findingsArgs](raw)
	if err != nil {
		return failure(err.Error())
	}
	minSev, err := match.ParseSeverity(a.MinSeverity)
	if err != nil {
		return failure(err.Error())
	}
	limit := defaultLimit
	if a.Limit != nil {
		if *a.Limit < 1 || *a.Limit > maxLimit {
			return failure(fmt.Sprintf("limit must be between 1 and %d, not %d", maxLimit, *a.Limit))
		}
		limit = *a.Limit
	}
	cve := strings.ToUpper(strings.TrimSpace(a.CVE))
	if cve != "" && !cveID.MatchString(cve) {
		return failure(fmt.Sprintf("cve %q is not a CVE ID such as CVE-2024-4577", a.CVE))
	}
	host := normalizeHost(a.Host)
	snap, err := s.loadFindings()
	if err != nil {
		return failure(err.Error())
	}
	matched := []match.Finding{}
	for _, f := range snap.Findings {
		if f.Severity.Rank() >= minSev.Rank() && (host == "" || f.Host == host) && (cve == "" || f.CVE == cve) {
			matched = append(matched, f)
		}
	}
	shown := matched[:min(limit, len(matched))]

	var b strings.Builder
	fmt.Fprintf(&b, "Matching findings: %d of %d in the run of %s", len(matched), len(snap.Findings), when(snap.GeneratedAt))
	if snap.KEVVersion != "" {
		fmt.Fprintf(&b, " (CISA KEV catalog %s)", snap.KEVVersion)
	}
	b.WriteString(".\n")
	if len(shown) < len(matched) {
		fmt.Fprintf(&b, "Showing the %d most urgent; raise limit (at most %d) or narrow the filters to see more.\n", len(shown), maxLimit)
	}
	for i, f := range shown {
		fmt.Fprintf(&b, "%d. %s\n", i+1, findingLine(f))
	}
	return toolResult{
		Content: []content{{Type: "text", Text: b.String()}},
		StructuredContent: findingsData{
			Organization: snap.Organization,
			GeneratedAt:  snap.GeneratedAt,
			KEVVersion:   snap.KEVVersion,
			Total:        len(matched),
			Returned:     len(shown),
			Findings:     shown,
		},
	}
}

// findingLine describes a finding on one line.
func findingLine(f match.Finding) string {
	where := place(f.Host, f.Port)
	head := fmt.Sprintf("[%s, score %d] ", f.Severity, f.Score)
	switch f.Kind {
	case match.KindKEV:
		parts := []string{fmt.Sprintf("%s in %s on %s", f.CVE, product(f.Technology, f.Version), where)}
		if f.Name != "" {
			parts = append(parts, f.Name)
		}
		parts = append(parts, "added to CISA KEV "+f.DateAdded)
		if f.Ransomware {
			parts = append(parts, "used in ransomware campaigns")
		}
		if f.Forensics {
			parts = append(parts, "CISA asks for forensic triage")
		}
		parts = append(parts, confidence(f))
		if f.Packaged {
			parts = append(parts, "version from a distribution package, which may carry backported fixes")
		}
		if f.Condition != "" {
			parts = append(parts, "applies "+f.Condition)
		}
		return head + strings.Join(parts, " · ")
	case match.KindTLSExpired:
		return head + fmt.Sprintf("Expired TLS certificate on %s: %q expired on %s", where, clip(f.Subject), day(f.Expires))
	case match.KindTLSExpiring:
		return head + fmt.Sprintf("TLS certificate expiring soon on %s: %q expires on %s", where, clip(f.Subject), day(f.Expires))
	case match.KindAdminExposed:
		return head + fmt.Sprintf("%s admin interface reachable on %s", f.Technology, where)
	case match.KindExposedFile:
		line := fmt.Sprintf("%s at %q", fileKind(f.TechID), clip(f.URL))
		if f.Evidence != "" {
			line += fmt.Sprintf(" (%q)", clip(f.Evidence))
		}
		return head + line
	case match.KindSecret:
		line := secretKind(f.Technology) + " at " + secretPlace(f)
		if f.Evidence != "" {
			line += fmt.Sprintf(" · value %q, partly hidden", clip(f.Evidence))
		}
		return head + line
	case match.KindBreach:
		parts := []string{fmt.Sprintf("Accounts on %s in the data breach %q", f.Host, clip(f.Name))}
		if f.BreachDate != "" {
			parts = append(parts, "breached "+f.BreachDate)
		}
		parts = append(parts, plural(f.Accounts, "account"))
		if f.Passwords {
			parts = append(parts, "passwords exposed")
		}
		return head + strings.Join(parts, " · ")
	}
	if where == "" {
		return head + string(f.Kind)
	}
	return head + fmt.Sprintf("%s on %s", f.Kind, where)
}

// place says where a finding is: host and port, or the host alone for
// findings without a port, such as breaches of a domain.
func place(host string, port int) string {
	if port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// secretPlace says where a secret was found: the file, quoted because
// anyone who can add a file to a repository chooses its name, the line, and
// the commit when it was found in the Git history.
func secretPlace(f match.Finding) string {
	p := strconv.Quote(clip(f.File))
	if f.Line > 0 {
		p += " line " + strconv.Itoa(f.Line)
	}
	if c := f.Commit; c != "" {
		p += " (commit " + c[:min(len(c), 12)] + ")"
	}
	return p
}

func secretKind(name string) string {
	if name == "" {
		return "Secret in source code"
	}
	return "Secret in source code: " + name
}

// fileKinds names exposed files by the check that found them.
var fileKinds = map[string]string{
	"env":           "Exposed environment file",
	"git":           "Exposed .git directory",
	"server-status": "Public server status page",
}

func fileKind(check string) string {
	if name, ok := fileKinds[check]; ok {
		return name
	}
	return "Exposed file"
}

func confidence(f match.Finding) string {
	switch {
	case f.RuledOut():
		return "ruled out: the version seen is outside the affected range"
	case f.Confidence == match.ConfidenceVersion:
		return "the version seen is in the affected range"
	case f.Version == "":
		return "version not shown, so it may already be fixed"
	}
	return "version not checked against the fix"
}

// plainVersion matches versions that are safe to show as they are.
var plainVersion = regexp.MustCompile(`^[0-9A-Za-z.+_~\-]{1,32}$`)

// product names a product and its version. A version that is long or holds
// unusual characters comes from a hostile server, so it is quoted.
func product(name, version string) string {
	switch {
	case version == "":
		return name
	case plainVersion.MatchString(version):
		return name + " " + version
	}
	return name + " " + strconv.Quote(clip(version))
}

type inventoryArgs struct {
	Host string `json:"host"`
}

type inventoryData struct {
	Organization string            `json:"organization"`
	GeneratedAt  time.Time         `json:"generatedAt"`
	Hosts        int               `json:"hosts"`
	Services     int               `json:"services"`
	Products     int               `json:"products"`
	Truncated    bool              `json:"truncated,omitempty"`
	Assets       []inventory.Asset `json:"assets"`
}

// sources describes how a host was found, by inventory source.
var sources = map[string]string{
	"host":     "listed in the scope",
	"domain":   "authorised domain",
	"ct":       "certificate transparency",
	"tls-san":  "name in a certificate",
	"redirect": "redirect target",
	"range":    "address in an authorised range",
}

func (s *Server) inventoryTool(_ context.Context, raw json.RawMessage) toolResult {
	a, err := decodeArgs[inventoryArgs](raw)
	if err != nil {
		return failure(err.Error())
	}
	inv, err := s.loadInventory()
	if err != nil {
		return failure(err.Error())
	}
	assets := inv.Assets
	if host := normalizeHost(a.Host); host != "" {
		assets = slices.DeleteFunc(slices.Clone(assets), func(x inventory.Asset) bool { return normalizeHost(x.Host) != host })
		if len(assets) == 0 {
			return textResult(fmt.Sprintf("No host %q in the inventory of %s, which lists %s. Call hejnal_inventory without host to see them all.",
				a.Host, when(inv.GeneratedAt), plural(len(inv.Assets), "host")))
		}
	}
	sel := &inventory.Inventory{Assets: assets}
	hosts, services, products := sel.Counts()
	data := inventoryData{
		Organization: inv.Organization,
		GeneratedAt:  inv.GeneratedAt,
		Hosts:        hosts,
		Services:     services,
		Products:     products,
		Assets:       assets[:min(len(assets), maxHosts)],
		Truncated:    len(assets) > maxHosts,
	}
	if data.Assets == nil {
		data.Assets = []inventory.Asset{}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Inventory of %s for %s: %s, %s, %s.\n", when(inv.GeneratedAt), inv.Organization,
		plural(hosts, "host"), plural(services, "service"), plural(products, "recognised product"))
	if data.Truncated {
		fmt.Fprintf(&b, "Showing the first %d hosts; pass host to see another one.\n", maxHosts)
	}
	for _, x := range data.Assets {
		b.WriteString("\n" + x.Host)
		how := sources[x.Source]
		if how == "" {
			how = x.Source
		}
		if ips := slices.DeleteFunc(slices.Clone(x.IPs), func(ip string) bool { return ip == x.Host }); len(ips) > 0 {
			how += "; " + strings.Join(ips, ", ")
		}
		if how != "" {
			b.WriteString(" (" + how + ")")
		}
		b.WriteString("\n")
		if len(x.Services) == 0 {
			b.WriteString("  no open web ports found\n")
		}
		for _, svc := range x.Services {
			fmt.Fprintf(&b, "  • %s\n", serviceLine(svc))
		}
		for _, e := range x.Errors {
			fmt.Fprintf(&b, "  ! %s\n", clip(e))
		}
	}
	return toolResult{Content: []content{{Type: "text", Text: b.String()}}, StructuredContent: data}
}

// serviceLine describes a service. Titles, banners and certificate names come
// from the checked systems, so they are quoted and shortened.
func serviceLine(svc inventory.Service) string {
	parts := []string{fmt.Sprintf("port %d (%s)", svc.Port, svc.Scheme)}
	if svc.URL != "" {
		parts = append(parts, strconv.Quote(clip(svc.URL)))
	}
	if svc.FinalURL != "" {
		parts = append(parts, "redirects to "+strconv.Quote(clip(svc.FinalURL)))
	}
	if svc.Status != 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", svc.Status))
	}
	if svc.Title != "" {
		parts = append(parts, fmt.Sprintf("title %q", clip(svc.Title)))
	}
	if svc.Server != "" {
		parts = append(parts, fmt.Sprintf("server %q", clip(svc.Server)))
	}
	if svc.Banner != "" {
		parts = append(parts, fmt.Sprintf("banner %q", clip(svc.Banner)))
	}
	if svc.TLS != nil {
		parts = append(parts, fmt.Sprintf("certificate %q expires on %s", clip(svc.TLS.Subject), svc.TLS.NotAfter.UTC().Format("2006-01-02")))
	}
	if len(svc.Technologies) == 0 {
		parts = append(parts, "no product recognised")
	} else {
		var techs []string
		for _, t := range svc.Technologies {
			desc := product(t.Name, t.Version) + " (" + t.Category
			if t.Admin {
				desc += ", admin interface"
			}
			techs = append(techs, desc+")")
		}
		parts = append(parts, "products: "+strings.Join(techs, ", "))
	}
	if len(svc.Exposures) > 0 {
		var files []string
		for _, x := range svc.Exposures {
			files = append(files, fmt.Sprintf("%q (%s)", clip(x.Path), strings.ToLower(fileKind(x.Kind))))
		}
		parts = append(parts, "readable files: "+strings.Join(files, ", "))
	}
	return strings.Join(parts, " · ")
}

type nis2Args struct {
	Lang string `json:"lang"`
}

func (s *Server) nis2Tool(_ context.Context, raw json.RawMessage) toolResult {
	a, err := decodeArgs[nis2Args](raw)
	if err != nil {
		return failure(err.Error())
	}
	lang, err := s.langArg(a.Lang)
	if err != nil {
		return failure(err.Error())
	}
	snap, err := s.loadFindings()
	if err != nil {
		return failure(err.Error())
	}
	var buf bytes.Buffer
	if err := report.NIS2(&buf, snap.Findings, engine.Meta(snap, lang)); err != nil {
		return failure("could not write the NIS2 draft: " + err.Error())
	}
	return textResult(buf.String())
}

// runTool checks the scope now and summarises what changed. It never marks
// findings as reported, so the command line still announces them.
func (s *Server) runTool(ctx context.Context, raw json.RawMessage) toolResult {
	if _, err := decodeArgs[noArgs](raw); err != nil {
		return failure(err.Error())
	}
	sc, err := s.scope()
	if err == nil && sc == nil {
		err = errors.New("no scope is configured")
	}
	if err != nil {
		s.logf("mcp: cannot start a run: %v", err)
		return failure("cannot start a run: " + err.Error())
	}
	s.logf("mcp: run started for %s", sc.Organization)
	res, err := s.engine.Run(ctx, sc)
	if err != nil {
		s.logf("mcp: run failed: %v", err)
		return failure("the run failed: " + err.Error())
	}
	text, sum := summarize(res.Snapshot, res.Changes)
	s.logf("mcp: run finished: %d open items", sum.OpenItems)
	text = "Run finished.\n" + text + "Nothing was marked as reported, so `hejnal run` still announces these changes.\n"
	return toolResult{Content: []content{{Type: "text", Text: text}}, StructuredContent: sum}
}

// item is one item to fix in a summary.
type item struct {
	// Key identifies the item across runs.
	Key        string         `json:"key"`
	Kind       match.Kind     `json:"kind"`
	Host       string         `json:"host"`
	Port       int            `json:"port"`
	Technology string         `json:"technology,omitempty"`
	Version    string         `json:"version,omitempty"`
	Severity   match.Severity `json:"severity"`
	Score      int            `json:"score"`
	CVEs       []string       `json:"cves,omitempty"`
	Title      string         `json:"title"`
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type summary struct {
	Organization string    `json:"organization"`
	GeneratedAt  time.Time `json:"generatedAt"`
	KEVVersion   string    `json:"kevVersion"`
	EPSSDate     string    `json:"epssDate,omitempty"`
	Hosts        int       `json:"hosts"`
	Services     int       `json:"services"`
	Products     int       `json:"products"`
	// OpenItems counts the items to fix; Open splits them by severity.
	OpenItems int            `json:"openItems"`
	Open      severityCounts `json:"open"`
	// FirstReport is true when nothing was reported before, so every open
	// item is new.
	FirstReport bool   `json:"firstReport"`
	New         []item `json:"new"`
	Resolved    []item `json:"resolved"`
	// RuledOut counts flaws the version check rules out. They are not open.
	RuledOut int `json:"ruledOut"`
}

// summarize describes the latest findings and what changed since the last
// report, as text and as structured data.
func summarize(snap *state.Snapshot, ch engine.Changes) (string, summary) {
	active := match.Active(snap.Findings)
	open := match.Groups(active)
	added, resolved := match.Groups(ch.Added), match.Groups(ch.Resolved)
	sum := summary{
		Organization: snap.Organization,
		GeneratedAt:  snap.GeneratedAt,
		KEVVersion:   snap.KEVVersion,
		EPSSDate:     snap.EPSSDate,
		Hosts:        snap.Assets,
		Services:     snap.Services,
		Products:     snap.Technologies,
		OpenItems:    len(open),
		FirstReport:  ch.First,
		New:          items(added),
		Resolved:     items(resolved),
		RuledOut:     len(snap.Findings) - len(active),
	}
	for _, g := range open {
		switch g.Severity {
		case match.Critical:
			sum.Open.Critical++
		case match.High:
			sum.Open.High++
		case match.Medium:
			sum.Open.Medium++
		case match.Low:
			sum.Open.Low++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Hejnal · %s\n", snap.Organization)
	fmt.Fprintf(&b, "Latest run: %s, checking %s, %s and %s.",
		when(snap.GeneratedAt), plural(snap.Assets, "host"), plural(snap.Services, "service"), plural(snap.Technologies, "product"))
	if snap.KEVVersion != "" {
		fmt.Fprintf(&b, " CISA KEV catalog %s.", snap.KEVVersion)
	}
	o := sum.Open
	fmt.Fprintf(&b, "\nOpen items: %d (critical %d · high %d · medium %d · low %d).\n", len(open), o.Critical, o.High, o.Medium, o.Low)
	if ch.First {
		b.WriteString("Nothing has been reported yet, so every open item is new.\n")
		listItems(&b, "", added)
	} else {
		fmt.Fprintf(&b, "Since the last report: %d new, %d resolved.\n", len(added), len(resolved))
		listItems(&b, "New:", added)
		listItems(&b, "Resolved:", resolved)
	}
	if sum.RuledOut > 0 {
		fmt.Fprintf(&b, "The version check rules out %s, which are not counted as open.\n", plural(sum.RuledOut, "flaw"))
	}
	if len(open) > 0 {
		b.WriteString("Call hejnal_fix_list for what to do about each item.\n")
	}
	return b.String(), sum
}

func listItems(b *strings.Builder, heading string, groups []match.Group) {
	if len(groups) == 0 {
		return
	}
	if heading != "" {
		b.WriteString(heading + "\n")
	}
	for i, g := range groups {
		if i == maxListed {
			fmt.Fprintf(b, "• …and %d more\n", len(groups)-maxListed)
			break
		}
		fmt.Fprintf(b, "• [%s] %s\n", g.Severity, title(g))
	}
}

func items(groups []match.Group) []item {
	out := []item{}
	for _, g := range groups {
		it := item{Key: g.Key, Kind: g.Kind, Host: g.Host, Port: g.Port, Technology: g.Technology, Version: g.Version,
			Severity: g.Severity, Score: g.Score, Title: title(g)}
		for _, f := range g.Findings {
			if f.CVE != "" {
				it.CVEs = append(it.CVEs, f.CVE)
			}
		}
		out = append(out, it)
	}
	return out
}

// title names an item to fix, as the fix list does.
func title(g match.Group) string {
	where := place(g.Host, g.Port)
	switch g.Kind {
	case match.KindKEV:
		var cves []string
		for i, f := range g.Findings {
			if i == 3 {
				cves = append(cves, fmt.Sprintf("+%d more", len(g.Findings)-3))
				break
			}
			cves = append(cves, f.CVE)
		}
		return fmt.Sprintf("%s on %s: %s", g.Technology, where, strings.Join(cves, ", "))
	case match.KindTLSExpired:
		return "Expired TLS certificate on " + where
	case match.KindTLSExpiring:
		return "TLS certificate expiring soon on " + where
	case match.KindAdminExposed:
		return fmt.Sprintf("%s admin interface reachable on %s", g.Technology, where)
	case match.KindExposedFile:
		return fileKind(g.TechID) + " on " + where
	case match.KindSecret:
		// One secret to replace, wherever it was found.
		t := secretKind(g.Technology) + " at " + secretPlace(g.Findings[0])
		if more := len(g.Findings) - 1; more > 0 {
			t += " and " + plural(more, "more place")
		}
		return t
	case match.KindBreach:
		return "Accounts on " + g.Host + " in known data breaches"
	}
	if where == "" {
		return string(g.Kind)
	}
	return fmt.Sprintf("%s on %s", g.Kind, where)
}

// normalizeHost writes a host the way findings do: lower case, without a
// trailing dot or brackets, and IP addresses in their canonical form.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.WithZone("").Unmap().String()
	}
	return h
}

func when(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func day(t *time.Time) string {
	if t == nil {
		return "an unknown date"
	}
	return t.UTC().Format("2006-01-02")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// clip shortens text copied from checked systems.
func clip(s string) string {
	const maxRunes = 120
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	return string([]rune(s)[:maxRunes]) + "…"
}
