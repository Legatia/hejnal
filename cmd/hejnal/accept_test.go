package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// runAtTime runs a command with the clock set to at.
func (h *harness) runAtTime(at time.Time, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.now = func() time.Time { return at }
	code = a.run(context.Background(), args)
	return code, out.String(), errOut.String()
}

// sent returns the chat messages sent so far.
func (h *harness) sent() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.messages)
}

// headingRE finds an item's product and ID in a fix list heading.
var headingRE = regexp.MustCompile("(?m)^### \\d+\\. (\\S+) on \\S+ · `([0-9a-f]{8})`$")

// itemIDs reads the IDs of the items in the saved fix list, by product.
func itemIDs(t *testing.T, h *harness) map[string]string {
	t.Helper()
	fix, err := os.ReadFile(filepath.Join(h.state, "fixlist.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, m := range headingRE.FindAllStringSubmatch(string(fix), -1) {
		ids[m[1]] = m[2]
	}
	if ids["WordPress"] == "" || ids["PHP"] == "" {
		t.Fatalf("no item IDs in the fix list:\n%s", fix)
	}
	return ids
}

func (h *harness) accept(args ...string) (int, string, string) {
	return h.run(append([]string{"accept", "-state", h.state}, args...)...)
}

func TestAcceptEndToEnd(t *testing.T) {
	h := newHarness(t)
	if code, _, errOut := h.run(h.runArgs("-fail-on", "high")...); code != exitFindings {
		t.Fatalf("first run: code %d\n%s", code, errOut)
	}
	wp := itemIDs(t, h)["WordPress"]

	code, out, errOut := h.accept("-item", wp, "-reason", "Version 6.8.3 has the fixes", "-by", "Anna Nowak")
	if code != exitOK || !strings.Contains(out, "Accepted "+wp+", WordPress on 127.0.0.1:") || !strings.Contains(out, "until 2027-02-02 (2 findings).") {
		t.Fatalf("accept: code %d\n%s%s", code, out, errOut)
	}
	if st, err := os.Stat(filepath.Join(h.state, state.AcceptedFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v", state.AcceptedFile, err)
	}

	// The fix list shows the item apart straight away.
	code, out, _ = h.run("report", "fixlist", "-state", h.state)
	for _, want := range []string{"**Fix now: 1 · This week: 0", "## Accepted", "- `" + wp + "` WordPress on 127.0.0.1:",
		"reason: Version 6.8.3 has the fixes · accepted by Anna Nowak · until 2027-02-02"} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("fix list is missing %q:\n%s", want, out)
		}
	}
	if regexp.MustCompile(`### \d+\. WordPress`).MatchString(out) {
		t.Errorf("the accepted item is still listed to fix:\n%s", out)
	}

	code, out, _ = h.accept("-list")
	for _, want := range []string{"ITEM", wp + "  2027-02-02  Anna Nowak  WordPress on 127.0.0.1:", "Version 6.8.3 has the fixes", "Accepted items: 1, expired: 0."} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("list is missing %q:\n%s", want, out)
		}
	}

	// The next run counts the item apart and has nothing new to send.
	code, out, _ = h.run(h.runArgs("-fail-on", "high")...)
	if code != exitOK || !strings.Contains(out, "New: 0 · Resolved: 0 · Open: 1 (critical 1 · high 0 · medium 0 · low 0) · Accepted: 1") || len(h.sent()) != 1 {
		t.Errorf("second run: code %d, %d messages\n%s", code, len(h.sent()), out)
	}
	// The findings file marks the accepted findings, with the reason and expiry.
	data, err := os.ReadFile(filepath.Join(h.state, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap state.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, f := range snap.Findings {
		if f.Accepted != nil {
			accepted++
			if f.TechID != "wordpress" || f.Accepted.Reason != "Version 6.8.3 has the fixes" || f.Accepted.Until != "2027-02-02" {
				t.Errorf("%s: %+v", f.Key, f.Accepted)
			}
		}
	}
	if accepted != 2 {
		t.Errorf("%d findings marked accepted, want 2", accepted)
	}

	// Accepting the item again replaces the acceptance.
	code, out, _ = h.accept("-item", strings.ToUpper(wp), "-reason", "Checked again", "-until", "2027-11-04")
	if code != exitOK || !strings.Contains(out, "Updated the acceptance of "+wp) || !strings.Contains(out, "until 2027-11-04") {
		t.Errorf("accepting again: code %d\n%s", code, out)
	}
	if _, out, _ = h.accept("-list"); strings.Count(out, wp) != 1 || !strings.Contains(out, "Checked again") || !strings.Contains(out, "2027-11-04") {
		t.Errorf("list after accepting again:\n%s", out)
	}

	// Removing the acceptance opens the item again, as news.
	if code, out, _ = h.accept("-remove", wp); code != exitOK || !strings.Contains(out, "Removed the acceptance of "+wp+", WordPress on 127.0.0.1:") {
		t.Errorf("remove: code %d\n%s", code, out)
	}
	if _, out, _ = h.accept("-list"); !strings.Contains(out, "No accepted items.") {
		t.Errorf("list after removing:\n%s", out)
	}
	if code, _, _ = h.run(h.runArgs("-fail-on", "high")...); code != exitFindings || len(h.sent()) != 2 {
		t.Errorf("run after removing: code %d, %d messages", code, len(h.sent()))
	}
}

// switchSite serves WordPress on PHP, or a page without them while plain is
// set, and points the harness's scope at itself.
func switchSite(t *testing.T, h *harness) *atomic.Bool {
	t.Helper()
	plain := &atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if plain.Load() {
			io.WriteString(w, `<html><head><title>Back soon</title></head></html>`)
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.12")
		io.WriteString(w, `<html><head><title>Sklep</title><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	scope := `{"organization": "Sklep Sp. z o.o.", "authorization": {"confirmedBy": "Anna Nowak, IT", "date": "2026-11-01", "statement": "We own this system."}, "hosts": ["127.0.0.1"], "ports": [` + u.Port() + `]}`
	if err := os.WriteFile(h.scope, []byte(scope), 0o600); err != nil {
		t.Fatal(err)
	}
	return plain
}

// TestAcceptedFindingsStayOutOfAlertsAndExitStatus runs the same checks
// with and without acceptances while the site goes away and comes back:
// its flaws are news again only where nobody accepted them.
func TestAcceptedFindingsStayOutOfAlertsAndExitStatus(t *testing.T) {
	h := newHarness(t)
	plain := switchSite(t, h)
	other := filepath.Join(h.dir, "other")
	both := func() (accepted, unaccepted int, out string) {
		accepted, out, _ = h.run(h.runArgs("-fail-on", "high")...)
		unaccepted, _, _ = h.run(append(h.runArgs("-fail-on", "high"), "-state", other)...)
		return accepted, unaccepted, out
	}
	if a, b, _ := both(); a != exitFindings || b != exitFindings || len(h.sent()) != 2 {
		t.Fatalf("first runs: %d and %d, %d messages", a, b, len(h.sent()))
	}
	ids := itemIDs(t, h)
	for _, id := range []string{ids["WordPress"], ids["PHP"]} {
		if code, out, errOut := h.accept("-item", id, "-reason", "Patched last week"); code != exitOK {
			t.Fatalf("accept %s: %d\n%s%s", id, code, out, errOut)
		}
	}
	// The site is down for a run: its flaws are resolved, which is not news.
	plain.Store(true)
	if a, b, _ := both(); a != exitOK || b != exitOK || len(h.sent()) != 2 {
		t.Fatalf("runs while down: %d and %d, %d messages", a, b, len(h.sent()))
	}
	// It is back. Its flaws are news again, but only where nobody accepted them.
	plain.Store(false)
	a, b, out := both()
	if a != exitOK || !strings.Contains(out, "New: 0 · Resolved: 0 · Open: 0 (critical 0 · high 0 · medium 0 · low 0) · Accepted: 2") {
		t.Errorf("run with acceptances: code %d\n%s", a, out)
	}
	if msgs := h.sent(); b != exitFindings || len(msgs) != 3 || !strings.Contains(msgs[2], "New: 2") {
		t.Errorf("run without acceptances: code %d, messages %q", b, msgs)
	}
}

// writeCatalogWithout writes the sample catalog without some of its flaws.
func writeCatalogWithout(t *testing.T, path string, cves ...string) {
	t.Helper()
	data, err := os.ReadFile(kevSample)
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]any
	if err := json.Unmarshal(data, &cat); err != nil {
		t.Fatal(err)
	}
	var kept []any
	for _, v := range cat["vulnerabilities"].([]any) {
		if !slices.Contains(cves, v.(map[string]any)["cveID"].(string)) {
			kept = append(kept, v)
		}
	}
	cat["vulnerabilities"], cat["count"] = kept, len(kept)
	if data, err = json.Marshal(cat); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNewFlawReopensAcceptedItem(t *testing.T) {
	h := newHarness(t)
	older := filepath.Join(h.dir, "kev-older.json")
	writeCatalogWithout(t, older, "CVE-2026-119977")
	withCatalog := func(kev string) []string {
		args := h.runArgs("-fail-on", "high")
		args[slices.Index(args, kevSample)] = kev
		return args
	}
	if code, _, errOut := h.run(withCatalog(older)...); code != exitFindings {
		t.Fatalf("first run: %d\n%s", code, errOut)
	}
	wp := itemIDs(t, h)["WordPress"]
	if code, out, _ := h.accept("-item", wp, "-reason", "Version 6.8.3 has the fix"); code != exitOK || !strings.Contains(out, "(1 finding)") {
		t.Fatalf("accept: %d\n%s", code, out)
	}
	if code, _, _ := h.run(withCatalog(older)...); code != exitOK || len(h.sent()) != 1 {
		t.Fatalf("run with nothing new: %d, %d messages", code, len(h.sent()))
	}

	// CISA adds a new WordPress flaw: the item is back with it alone.
	code, _, errOut := h.run(withCatalog(kevSample)...)
	msgs := h.sent()
	if code != exitFindings || len(msgs) != 2 {
		t.Fatalf("run with the new flaw: %d, %d messages\n%s", code, len(msgs), errOut)
	}
	if !regexp.MustCompile(`WordPress on 127\.0\.0\.1:\d+: CVE-2026-119977\n`).MatchString(msgs[1]) || strings.Contains(msgs[1], "CVE-2026-87902") {
		t.Errorf("message about the new flaw:\n%s", msgs[1])
	}
	fix, err := os.ReadFile(filepath.Join(h.state, "fixlist.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"· `" + wp + "`\n\n- **Accepted earlier:** Part of this item was accepted until 2027-02-02",
		"- **Why:** Known exploited flaws in this product: 1.",
		"**CVE-2026-119977**",
		"- `" + wp + "` WordPress on 127.0.0.1:",
		": CVE-2026-87902 · reason: Version 6.8.3 has the fix · until 2027-02-02",
	} {
		if !strings.Contains(string(fix), want) {
			t.Errorf("fix list is missing %q:\n%s", want, fix)
		}
	}
	if strings.Contains(string(fix), "**CVE-2026-87902**") {
		t.Errorf("the accepted flaw is listed to fix:\n%s", fix)
	}
}

func TestAcceptanceExpires(t *testing.T) {
	h := newHarness(t)
	if code, _, _ := h.run(h.runArgs("-fail-on", "high")...); code != exitFindings {
		t.Fatalf("first run: %d", code)
	}
	ids := itemIDs(t, h)
	for _, id := range []string{ids["WordPress"], ids["PHP"]} {
		if code, out, _ := h.accept("-item", id, "-reason", "Patched", "-until", "2026-11-10"); code != exitOK {
			t.Fatalf("accept: %d\n%s", code, out)
		}
	}
	if code, _, _ := h.run(h.runArgs("-fail-on", "high")...); code != exitOK || len(h.sent()) != 1 {
		t.Fatalf("run while accepted: %d, %d messages", code, len(h.sent()))
	}
	if _, out, _ := h.accept("-list"); !strings.Contains(out, "Accepted items: 2, expired: 0.") {
		t.Errorf("list before expiry:\n%s", out)
	}

	// The day after the last day, both items are open again, and news.
	later := time.Date(2026, 11, 11, 7, 0, 0, 0, time.UTC)
	code, _, errOut := h.runAtTime(later, h.runArgs("-fail-on", "high")...)
	msgs := h.sent()
	if code != exitFindings || len(msgs) != 2 || strings.Count(msgs[1], "· acceptance expired") != 2 {
		t.Fatalf("run after expiry: %d, messages %q\n%s", code, msgs, errOut)
	}
	fix, _ := os.ReadFile(filepath.Join(h.state, "fixlist.md"))
	if strings.Count(string(fix), "- **Acceptance expired:** This item was accepted until 2026-11-10.") != 2 || strings.Contains(string(fix), "## Accepted") {
		t.Errorf("fix list after expiry:\n%s", fix)
	}
	_, out, _ := h.runAtTime(later, "accept", "-list", "-state", h.state)
	if strings.Count(out, "2026-11-10 (expired)") != 2 || !strings.Contains(out, "Accepted items: 2, expired: 2. An expired acceptance covers nothing") {
		t.Errorf("list after expiry:\n%s", out)
	}
}

func TestAcceptRefusesBadInput(t *testing.T) {
	h := newHarness(t)
	if code, _, errOut := h.accept("-item", "4ad98b95", "-reason", "Patched"); code != exitError || !strings.Contains(errOut, "no findings yet") {
		t.Errorf("before the first run: %d %q", code, errOut)
	}
	if code, _, _ := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run: %d", code)
	}
	wp := itemIDs(t, h)["WordPress"]
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-item", wp}, "-reason is required"},
		{[]string{"-item", wp, "-reason", " \n\t "}, "-reason is required"},
		{[]string{"-item", wp, "-reason", strings.Repeat("ż", 501)}, "-reason is longer than 500 characters"},
		{[]string{"-item", wp, "-reason", "Patched", "-by", strings.Repeat("x", 101)}, "-by is longer than 100 characters"},
		{[]string{"-item", wp, "-reason", "Patched", "-until", "2027-11-05"}, "-until 2027-11-05 is more than a year away"},
		{[]string{"-item", wp, "-reason", "Patched", "-until", "2026-11-03"}, "-until 2026-11-03 is in the past"},
		{[]string{"-item", wp, "-reason", "Patched", "-until", "05.11.2026"}, "-until must be a date such as 2027-02-02"},
		{[]string{"-item", "deadbeef", "-reason", "Patched"}, "there is no item deadbeef in the findings of 2026-11-04 12:00 UTC"},
		{[]string{"-item", "WordPress", "-reason", "Patched"}, `"wordpress" is not an item ID`},
		{[]string{"-item", wp[:7], "-reason", "Patched"}, "is not an item ID"},
		{[]string{"-item", wp, "-list", "-reason", "Patched"}, "use only one of -item, -list and -remove"},
		{[]string{"-list", "-until", "2027-01-01"}, "-reason, -until and -by go only with -item"},
		{[]string{"-remove", wp}, "item " + wp + " is not accepted"},
		{[]string{"-remove", "nope"}, `"nope" is not an item ID`},
		{[]string{"-item", wp, "-reason", "Patched", "extra"}, `unexpected argument "extra"`},
		{nil, "use -item, -list or -remove"},
	} {
		code, out, errOut := h.accept(c.args...)
		if code != exitError || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: code %d, stderr %q, want %q", c.args, code, errOut, c.want)
		}
		if out != "" {
			t.Errorf("%q printed %q", c.args, out)
		}
	}
	if _, err := os.Stat(filepath.Join(h.state, state.AcceptedFile)); !os.IsNotExist(err) {
		t.Errorf("a refused acceptance was saved: %v", err)
	}

	// An item whose flaws the version check rules out has nothing to accept.
	dir := filepath.Join(h.dir, "ruled-out")
	ruledOut := match.Finding{Key: "kev|w|443|CVE-2024-4577", Kind: match.KindKEV, Host: "w", Port: 443, TechID: "php", Technology: "PHP",
		CVE: "CVE-2024-4577", Version: "8.3.12", Score: 20, Severity: match.Low, Confidence: match.ConfidenceRuledOut}
	if err := (state.Store{Dir: dir}).SaveFindings(&state.Snapshot{GeneratedAt: testNow, Findings: []match.Finding{ruledOut}}); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := h.run("accept", "-state", dir, "-item", match.ItemID("kev|w|443|php"), "-reason", "Patched"); code != exitError ||
		!strings.Contains(errOut, "PHP on w:443, has nothing open to accept") {
		t.Errorf("ruled-out item: %d %q", code, errOut)
	}

	// Today and a year from today are the limits.
	if code, _, errOut := h.accept("-item", wp, "-reason", "Patched", "-until", "2027-11-04"); code != exitOK {
		t.Errorf("a year: %d %q", code, errOut)
	}
	if code, _, errOut := h.accept("-item", itemIDs(t, h)["PHP"], "-reason", "Patched", "-until", "2026-11-04"); code != exitOK {
		t.Errorf("today: %d %q", code, errOut)
	}
	if code, out, _ := h.run("accept", "-h"); code != exitOK || out != "" {
		t.Errorf("-h: %d %q", code, out)
	}
}

func TestAcceptedReasonsAreEscaped(t *testing.T) {
	h := newHarness(t)
	if code, _, _ := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run: %d", code)
	}
	wp := itemIDs(t, h)["WordPress"]
	reason := "Patched\n## Fake heading <img src=x onerror=alert(1)> [click](https://evil.example) | *x*"
	if code, out, errOut := h.accept("-item", wp, "-reason", reason, "-by", "<b>Mallory</b>"); code != exitOK {
		t.Fatalf("accept: %d\n%s%s", code, out, errOut)
	}
	_, fix, _ := h.run("report", "fixlist", "-state", h.state)
	for _, bad := range []string{"<img", "<b>", "\n## Fake", "[click](", "*x*"} {
		if strings.Contains(fix, bad) {
			t.Errorf("the fix list contains %q unescaped:\n%s", bad, fix)
		}
	}
	for _, want := range []string{"reason: Patched ## Fake heading &lt;img src=x onerror=alert(1)&gt; \\[click\\](https://evil.example) \\| \\*x\\*",
		"accepted by &lt;b&gt;Mallory&lt;/b&gt;"} {
		if !strings.Contains(fix, want) {
			t.Errorf("the fix list is missing %q:\n%s", want, fix)
		}
	}
	// The list keeps each acceptance on one line.
	_, out, _ := h.accept("-list")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 4 || !strings.Contains(lines[1], "Patched ## Fake heading") {
		t.Errorf("list:\n%s", out)
	}
}

func TestFindItemTellsApartItemsThatShareAnID(t *testing.T) {
	keys := []string{"kev|www.example.com|443|product-31981", "kev|www.example.com|443|product-53459"}
	if match.ItemID(keys[0]) != "b346f141" || match.ItemID(keys[1]) != "b346f141" {
		t.Fatal("the test keys no longer share an ID")
	}
	gs := []match.Group{{Key: keys[0]}, {Key: keys[1]}}
	if _, err := findItem(gs, "b346f141", testNow); err == nil ||
		!strings.Contains(err.Error(), "fits 2 items; use a longer one: b346f1410a3562e7 or b346f141951835c0") {
		t.Errorf("shared ID: %v", err)
	}
	if g, err := findItem(gs, "B346F141951835", testNow); err != nil || g.Key != keys[1] {
		t.Errorf("longer ID: %+v, %v", g, err)
	}
}
