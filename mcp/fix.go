package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/report"
)

// The tools a coding assistant fixes an item with: hejnal_code_scan checks
// the source directories the server was started with, and hejnal_live_check
// looks at one system in the scope. Each can say whether one item is still
// found, so the assistant can change the code or the system, check again and
// stop only when Hejnal no longer finds the item. Neither saves anything, so
// the fix list and what people were told stay as the last run left them.

const (
	// maxFixItems is how many items a check lists, most urgent first.
	maxFixItems = 50
	// maxLiveWait is the longest hejnal_live_check waits for a system to
	// come up, in seconds.
	maxLiveWait = 300
)

// fixItem is an item to fix, with what fixing it needs.
type fixItem struct {
	item
	// Todo says what to do about the item.
	Todo string `json:"todo,omitempty"`
	// Places are where the item was found: files and lines for an item in
	// code, the address for one on a system.
	Places []string `json:"places,omitempty"`
	// Ecosystem is the registry of a dependency, such as npm.
	Ecosystem string `json:"ecosystem,omitempty"`
	// FixedIn is the version that fixes every advisory of a dependency,
	// when there is one.
	FixedIn string `json:"fixedIn,omitempty"`
}

// itemCheck says whether a fresh look still finds one item.
type itemCheck struct {
	ID string `json:"id"`
	// Status is found, gone, moved (the same thing is now found under
	// another ID, in Now), not_found (nothing on record names the ID) or
	// unknown (this look cannot tell, for the reason in Why). Only gone
	// says the item is fixed.
	Status string `json:"status"`
	Why    string `json:"why,omitempty"`
	// Item is the item as found now or, when it is not, as last found.
	Item *fixItem `json:"item,omitempty"`
	Now  *fixItem `json:"now,omitempty"`
}

type codeScanData struct {
	Project   string    `json:"project"`
	ScannedAt time.Time `json:"scannedAt"`
	// Packages counts the dependencies read from lockfiles.
	Packages int      `json:"packages"`
	Notes    []string `json:"notes,omitempty"`
	// OpenItems counts the items to fix, whatever min_severity is.
	OpenItems     int        `json:"openItems"`
	AcceptedItems int        `json:"acceptedItems"`
	Items         []fixItem  `json:"items,omitempty"`
	Check         *itemCheck `json:"check,omitempty"`
}

type liveData struct {
	// Address is the address checked, without its path.
	Address string `json:"address"`
	// Status and Title are the answer of its front page.
	Status   int      `json:"status"`
	Title    string   `json:"title,omitempty"`
	FinalURL string   `json:"finalUrl,omitempty"`
	Products []string `json:"products,omitempty"`
	// CertificateUntil is the day the certificate expires.
	CertificateUntil string     `json:"certificateUntil,omitempty"`
	OpenItems        int        `json:"openItems"`
	AcceptedItems    int        `json:"acceptedItems"`
	Items            []fixItem  `json:"items,omitempty"`
	Check            *itemCheck `json:"check,omitempty"`
}

func fixItemOf(g match.Group) fixItem {
	it := fixItem{item: items([]match.Group{g})[0], Places: report.Places(g)}
	_, it.Todo = report.ItemText(g, "en")
	if g.Kind == match.KindDependency {
		it.Ecosystem = g.Findings[0].Ecosystem
		it.FixedIn = report.FixedIn(g)
	}
	return it
}

// writeFixItem describes one item on a few lines: its ID and title, what to
// do and where it is.
func writeFixItem(b *strings.Builder, head string, g match.Group) {
	fmt.Fprintf(b, "%s[%s] %s · item %s\n", head, g.Severity, title(g), g.ID())
	if _, todo := report.ItemText(g, "en"); todo != "" {
		fmt.Fprintf(b, "   What to do: %s\n", todo)
	}
	if g.Kind == match.KindDependency {
		if v := report.FixedIn(g); v != "" {
			fmt.Fprintf(b, "   Fixed in: %s\n", product("version", v))
		}
	}
	var places []string
	for _, p := range report.Places(g) {
		places = append(places, strconv.Quote(clip(p)))
	}
	if len(places) > 0 {
		fmt.Fprintf(b, "   Where: %s\n", strings.Join(places, ", "))
	}
}

// listFix writes the open items at or above a severity and returns them,
// with how many are open and how many people accepted.
func listFix(b *strings.Builder, found []match.Finding, minSev match.Severity) (shown []fixItem, open, accepted int) {
	groups := match.Groups(match.Open(found))
	_, acc := match.SplitAccepted(found)
	open, accepted = len(groups), len(match.Groups(acc))
	var listed []match.Group
	for _, g := range groups {
		if g.Severity.Rank() >= minSev.Rank() {
			listed = append(listed, g)
		}
	}
	fmt.Fprintf(b, "Open items: %d", open)
	if len(listed) != open {
		fmt.Fprintf(b, ", %d of them %s or above", len(listed), minSev)
	}
	b.WriteString(".\n")
	for i, g := range listed {
		if i == maxFixItems {
			fmt.Fprintf(b, "…and %d more: set min_severity to see fewer, or fix these first.\n", len(listed)-maxFixItems)
			break
		}
		writeFixItem(b, strconv.Itoa(i+1)+". ", g)
		shown = append(shown, fixItemOf(g))
	}
	if accepted > 0 {
		fmt.Fprintf(b, "Accepted with `hejnal accept` after a check, and not listed: %s.\n", plural(accepted, "item"))
	}
	return shown, open, accepted
}

// checkResult says what a fresh look found out about one item, as text and
// as structured data.
func checkResult(r engine.Recheck) (string, *itemCheck) {
	c := &itemCheck{ID: r.ID, Status: r.Status, Why: r.Why}
	if r.Group != nil && len(r.Group.Findings) > 0 {
		it := fixItemOf(*r.Group)
		c.Item = &it
	}
	var b strings.Builder
	switch r.Status {
	case engine.ItemFound:
		writeFixItem(&b, "Item "+r.ID+" is still found: ", *r.Group)
	case engine.ItemMoved:
		it := fixItemOf(*r.Now)
		c.Now = &it
		writeFixItem(&b, fmt.Sprintf("Item %s is not fixed: it is now item %s. ", r.ID, r.Now.ID()), *r.Now)
	case engine.ItemGone:
		fmt.Fprintf(&b, "Item %s is no longer found: %s\n", r.ID, title(*r.Group))
	case engine.ItemNotFound:
		fmt.Fprintf(&b, "Item %s is not found, and nothing on record names this ID: no saved result, and no earlier check in this session. "+
			"Hejnal cannot tell that the item was ever found here, so this does not say it is fixed. "+
			"Check the ID, and that the project or address is the one the item names.\n", r.ID)
	default:
		fmt.Fprintf(&b, "Cannot tell whether item %s is still there: %s.\n", r.ID, r.Why)
	}
	return b.String(), c
}

// itemArg reads the item argument of a check: an item's ID, or "".
func itemArg(v string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(v))
	if id != "" && !engine.ValidItemID(id) {
		return "", fmt.Errorf("item %q is not an item's ID: the fix list and each issue show it, such as 30c07628", clip(v))
	}
	return id, nil
}

// maxChecks is how many of a session's own checks are kept to compare with.
const maxChecks = 64

// known returns the findings a check of one item compares with: those the
// state directory holds, and those of this session's checks that found the
// item, so an item first seen in this session can later be told gone.
//
// A check that did not find the item is left out on purpose. What stands
// beside an item on record is another item; what turns up only after it is
// gone may be the same thing under a new ID, such as a package upgraded to
// a version that still has an advisory, and must keep counting as that
// however often the assistant asks.
func (s *Server) known(id string) (all []match.Finding, inSession bool, err error) {
	if all, err = engine.Known(s.store); err != nil {
		return nil, false, err
	}
	for _, fs := range s.checks {
		if engine.FindItem(fs, id) != nil {
			all, inSession = append(all, fs...), true
		}
	}
	return all, inSession, nil
}

// remember keeps what a check found for later checks in this session.
// Tool calls run one at a time, so nothing else reads it meanwhile.
func (s *Server) remember(fs []match.Finding) {
	if len(fs) == 0 {
		return
	}
	if len(s.checks) == maxChecks {
		s.checks = s.checks[1:]
	}
	s.checks = append(s.checks, fs)
}

// leakKey returns the key in the state directory that secret IDs are made
// with, or nil when there is none. It is read once and never made: IDs
// must stay the same through a session, and a check saves nothing.
func (s *Server) leakKey() ([]byte, error) {
	if !s.leakKeyRead {
		key, err := s.store.SavedLeakKey()
		if err != nil {
			return nil, err
		}
		s.leakKeyValue, s.leakKeyRead = key, true
	}
	return s.leakKeyValue, nil
}

type codeScanArgs struct {
	MinSeverity string `json:"min_severity"`
	Item        string `json:"item"`
}

// codeScanTool checks the source directories the server was started with.
func (s *Server) codeScanTool(ctx context.Context, raw json.RawMessage) toolResult {
	a, err := decodeArgs[codeScanArgs](raw)
	if err != nil {
		return failure(err.Error())
	}
	minSev, err := match.ParseSeverity(a.MinSeverity)
	if err != nil {
		return failure(err.Error())
	}
	id, err := itemArg(a.Item)
	if err != nil {
		return failure(err.Error())
	}
	req := s.code
	if req.FingerprintKey, err = s.leakKey(); err != nil {
		return failure(err.Error())
	}
	s.logf("mcp: code scan of %s started", req.Project)
	scan, err := s.engine.ScanCode(ctx, req)
	if err != nil {
		s.logf("mcp: code scan failed: %v", err)
		return failure("the code scan failed: " + err.Error())
	}
	accepted, err := s.store.LoadAccepted()
	if err != nil {
		return failure(err.Error())
	}
	found := match.MarkAccepted(scan.Findings, accepted, s.now())
	data := codeScanData{Project: scan.Project, ScannedAt: scan.ScannedAt, Packages: scan.Packages, Notes: scan.Notes}

	var b strings.Builder
	if id != "" {
		known, inSession, err := s.known(id)
		if err != nil {
			return failure(err.Error())
		}
		// A secret found earlier in this session got its ID from the same
		// key this scan used, whether or not the state directory has one.
		keyed := req.FingerprintKey != nil || inSession
		text, check := checkResult(engine.RecheckCode(id, scan, req, known, keyed))
		b.WriteString(text)
		data.Check = check
		_, acc := match.SplitAccepted(found)
		data.OpenItems, data.AcceptedItems = len(match.Groups(match.Open(found))), len(match.Groups(acc))
	} else {
		fmt.Fprintf(&b, "Code scan of %s: %s read from lockfiles.\n", strconv.Quote(clip(scan.Project)), plural(scan.Packages, "package"))
		data.Items, data.OpenItems, data.AcceptedItems = listFix(&b, found, minSev)
		if data.OpenItems > 0 {
			b.WriteString("After fixing an item, call hejnal_code_scan with item set to its ID: it is fixed when the status is gone.\n")
		}
	}
	for _, n := range scan.Notes {
		fmt.Fprintf(&b, "Note: %s\n", clip(n))
	}
	s.remember(scan.Findings)
	s.logf("mcp: code scan finished: %d open items", data.OpenItems)
	return toolResult{Content: []content{{Type: "text", Text: b.String()}}, StructuredContent: data}
}

type liveCheckArgs struct {
	URL         string `json:"url"`
	WaitSeconds *int   `json:"wait_seconds"`
	Item        string `json:"item"`
}

// liveCheckTool looks at one system in the scope, as `hejnal live` does.
func (s *Server) liveCheckTool(ctx context.Context, raw json.RawMessage) toolResult {
	a, err := decodeArgs[liveCheckArgs](raw)
	if err != nil {
		return failure(err.Error())
	}
	if strings.TrimSpace(a.URL) == "" {
		return failure("give the address to check as url, such as https://app.example.com")
	}
	wait := 0
	if a.WaitSeconds != nil {
		if wait = *a.WaitSeconds; wait < 0 || wait > maxLiveWait {
			return failure(fmt.Sprintf("set wait_seconds between 0 and %d, not %d", maxLiveWait, wait))
		}
	}
	id, err := itemArg(a.Item)
	if err != nil {
		return failure(err.Error())
	}
	t, err := engine.ParseLiveURL(a.URL)
	if err != nil {
		return failure("cannot check that address: " + err.Error())
	}
	sc, err := s.scope()
	if err == nil && sc == nil {
		err = errors.New("no scope is configured")
	}
	if err != nil {
		s.logf("mcp: cannot start a live check: %v", err)
		return failure("cannot start a check: " + err.Error())
	}
	// Refused before anything is contacted.
	if err := t.Allowed(sc, ""); err != nil {
		return failure("not checked: " + err.Error())
	}
	s.logf("mcp: live check of %s started", t.Shown)
	targets := []engine.LiveTarget{t}
	inv, problems, err := s.engine.LookLive(ctx, sc, targets, engine.LiveOptions{Checks: true, Wait: time.Duration(wait) * time.Second, Pause: s.livePause})
	if err != nil {
		s.logf("mcp: live check failed: %v", err)
		return failure("the check failed: " + err.Error())
	}
	if len(problems) > 0 {
		msg := "nothing to check: " + strings.Join(problems, "; ")
		if wait > 0 {
			return failure(fmt.Sprintf("%s (waited %d seconds)", msg, wait))
		}
		return failure(msg + "; wait_seconds gives a deploy time to come up")
	}
	snap, err := s.engine.Assess(ctx, inv)
	if err != nil {
		s.logf("mcp: live check failed: %v", err)
		return failure("the check failed: " + err.Error())
	}

	data := liveData{Address: t.Shown}
	var b strings.Builder
	if _, svc := engine.LiveService(inv, t); svc != nil {
		data.Status, data.Title, data.FinalURL = svc.Status, clip(svc.Title), clip(svc.FinalURL)
		fmt.Fprintf(&b, "Checked %s: status %d", t.Shown, svc.Status)
		if svc.Title != "" {
			fmt.Fprintf(&b, ", title %q", clip(svc.Title))
		}
		if svc.FinalURL != "" {
			fmt.Fprintf(&b, ", at %s", strconv.Quote(clip(svc.FinalURL)))
		}
		b.WriteString(".\n")
		for _, tech := range svc.Technologies {
			data.Products = append(data.Products, product(tech.Name, tech.Version))
		}
		if len(data.Products) > 0 {
			fmt.Fprintf(&b, "Products: %s.\n", strings.Join(data.Products, ", "))
		}
		if svc.TLS != nil {
			data.CertificateUntil = svc.TLS.NotAfter.UTC().Format(time.DateOnly)
			fmt.Fprintf(&b, "Certificate valid until %s.\n", data.CertificateUntil)
		}
	}
	if t.Path != "" {
		fmt.Fprintf(&b, "The check looks at the front page and at fixed paths, not at %s.\n", strconv.Quote(clip(t.Path)))
	}
	if id != "" {
		known, _, err := s.known(id)
		if err != nil {
			return failure(err.Error())
		}
		text, check := checkResult(engine.RecheckLive(id, snap.Findings, known, targets, true))
		b.WriteString(text)
		data.Check = check
		_, acc := match.SplitAccepted(snap.Findings)
		data.OpenItems, data.AcceptedItems = len(match.Groups(match.Open(snap.Findings))), len(match.Groups(acc))
	} else {
		data.Items, data.OpenItems, data.AcceptedItems = listFix(&b, snap.Findings, "")
		if data.OpenItems > 0 {
			b.WriteString("After fixing an item, call hejnal_live_check with the same url and item set to its ID: it is fixed when the status is gone.\n")
		}
	}
	b.WriteString("Nothing was saved: the fix list changes with the next run.\n")
	s.remember(snap.Findings)
	s.logf("mcp: live check of %s finished: %d open items", t.Shown, data.OpenItems)
	return toolResult{Content: []content{{Type: "text", Text: b.String()}}, StructuredContent: data}
}

// codeProject names the project of a code scan: the name given, or the
// first directory's.
func codeProject(req engine.CodeRequest) string {
	if req.Project != "" || len(req.Dirs) == 0 {
		return req.Project
	}
	abs, err := filepath.Abs(req.Dirs[0])
	if err != nil {
		return filepath.Base(req.Dirs[0])
	}
	return filepath.Base(abs)
}
