package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Legatia/hejnal/engine"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// fakeOSV answers as OSV does, with one advisory: lodash before 4.17.21.
func fakeOSV(t *testing.T) *httptest.Server {
	t.Helper()
	const adv = `{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash","modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string }
					Version string
				}
			}
			json.NewDecoder(r.Body).Decode(&req)
			var res []map[string]any
			for _, q := range req.Queries {
				if q.Package.Name == "lodash" && (q.Version == "4.17.20" || q.Version == "4.17.19") {
					res = append(res, map[string]any{"vulns": []map[string]any{{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z"}}})
				} else {
					res = append(res, map[string]any{})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": res})
		case "/v1/vulns/GHSA-35jh-r3h4-6jhm":
			io.WriteString(w, adv)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lockfile(version string) string {
	return `{"packages":{"node_modules/lodash":{"version":"` + version + `"},"node_modules/react":{"version":"18.2.0"}}}`
}

// codeServer makes a server that may check the project in dir.
func codeServer(t *testing.T, stateDir, proj string) (*Server, *logs) {
	t.Helper()
	e, err := engine.New(engine.Config{
		StateDir: stateDir,
		KEVFile:  kevSample,
		OSVURL:   fakeOSV(t).URL,
		NoEPSS:   true,
		NoCT:     true,
		NoNVD:    true,
		Timeout:  10 * time.Second,
		Now:      func() time.Time { return testNow },
		Logf:     (&logs{}).logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	l := &logs{}
	return NewServer(Config{Engine: e, Code: engine.CodeRequest{Dirs: []string{proj}}, Logf: l.logf}), l
}

func toolNames(t *testing.T, s *Server) ([]string, map[string]map[string]any) {
	t.Helper()
	resps := exchange(t, s, request(1, "tools/list", nil))
	var res struct {
		Tools []map[string]any `json:"tools"`
	}
	if len(resps) != 1 || json.Unmarshal(resps[0].Result, &res) != nil {
		t.Fatalf("tools/list: %+v", resps)
	}
	var names []string
	byName := map[string]map[string]any{}
	for _, tl := range res.Tools {
		name := tl["name"].(string)
		names = append(names, name)
		byName[name] = tl
	}
	return names, byName
}

const stripeKey = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc4eC39HqLyjWDarjtT1zdp7dc"

func TestCodeScanTool(t *testing.T) {
	dir := t.TempDir()
	proj, stateDir := filepath.Join(dir, "shop"), filepath.Join(dir, "state")
	writeFile(t, proj, "package-lock.json", lockfile("4.17.20"))
	writeFile(t, proj, "infra/main.tf", "resource \"aws_security_group\" \"ssh\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n")
	writeFile(t, proj, "config/app.env", "STRIPE_KEY="+stripeKey+"\n")
	s, l := codeServer(t, stateDir, proj)

	names, tools := toolNames(t, s)
	if !slices.Contains(names, "hejnal_code_scan") || slices.Contains(names, "hejnal_live_check") || slices.Contains(names, "hejnal_run") {
		t.Fatalf("tools = %v", names)
	}
	tl := tools["hejnal_code_scan"]
	if a, _ := tl["annotations"].(map[string]any); a["readOnlyHint"] != true || a["openWorldHint"] != true {
		t.Errorf("annotations = %v", tl["annotations"])
	}
	if d, _ := tl["description"].(string); !strings.Contains(d, strconvQuote(proj)) || !strings.Contains(d, `project "shop"`) || !strings.Contains(d, "saves nothing") {
		t.Errorf("description = %q", d)
	}
	check := func(args map[string]any) (toolResponse, codeScanData) {
		t.Helper()
		r := callOne(t, s, "hejnal_code_scan", args)
		if r.IsError {
			t.Fatalf("hejnal_code_scan %v failed: %s", args, r.text())
		}
		return r, structured[codeScanData](t, r)
	}
	status := func(id, want string) (toolResponse, codeScanData) {
		t.Helper()
		r, data := check(map[string]any{"item": id})
		if data.Check == nil || data.Check.ID != id || data.Check.Status != want {
			t.Fatalf("item %s: check = %+v, want status %s\n%s", id, data.Check, want, r.text())
		}
		if len(data.Items) != 0 {
			t.Errorf("a check of one item lists others: %+v", data.Items)
		}
		return r, data
	}

	// Before any check, nothing names an ID.
	if r, _ := status("00000000", "not_found"); !strings.Contains(r.text(), "does not say it is fixed") {
		t.Errorf("an unknown ID:\n%s", r.text())
	}

	r, data := check(nil)
	for _, want := range []string{
		`Code scan of "shop": 2 packages read from lockfiles.`,
		"Open items: 3.",
		"lodash 4.17.20",
		"Fixed in: version 4.17.21",
		`Where: "package-lock.json"`,
		`"infra/main.tf:`,
		`"config/app.env:`,
		"call hejnal_code_scan with item set to its ID",
	} {
		if !strings.Contains(r.text(), want) {
			t.Errorf("the scan's text is missing %q:\n%s", want, r.text())
		}
	}
	if strings.Contains(r.text(), stripeKey) || strings.Contains(string(r.StructuredContent), stripeKey) {
		t.Errorf("the scan shows a secret whole:\n%s\n%s", r.text(), r.StructuredContent)
	}
	if data.Project != "shop" || data.Packages != 2 || data.OpenItems != 3 || len(data.Items) != 3 || data.Check != nil {
		t.Fatalf("structured scan = %+v", data)
	}
	ids := map[string]string{}
	for _, it := range data.Items {
		if !engine.ValidItemID(it.ID) || it.Todo == "" || len(it.Places) == 0 || !strings.Contains(r.text(), "item "+it.ID) {
			t.Errorf("item %+v", it)
		}
		ids[string(it.Kind)] = it.ID
		if it.Kind == "dependency" && (it.Ecosystem != "npm" || it.FixedIn != "4.17.21" || it.Technology != "lodash" || it.Version != "4.17.20") {
			t.Errorf("dependency item = %+v", it)
		}
	}
	lodash, secret, sg := ids["dependency"], ids["secret"], ids["misconfig"]
	if lodash == "" || secret == "" || sg == "" {
		t.Fatalf("item kinds = %v", ids)
	}

	// min_severity narrows the list, not the count.
	r, data = check(map[string]any{"min_severity": "critical"})
	if data.OpenItems != 3 || len(data.Items) >= 3 || !strings.Contains(r.text(), "of them critical or above") {
		t.Errorf("min_severity critical: %+v\n%s", data, r.text())
	}

	r, data = status(lodash, "found")
	if !strings.Contains(r.text(), "Item "+lodash+" is still found: ") || strings.Contains(r.text(), "aws_security_group") || data.Check.Item == nil || data.Check.Item.ID != lodash {
		t.Errorf("while the package is there: %+v\n%s", data.Check, r.text())
	}

	// A version that still has an advisory is not a fix, however often
	// the assistant asks.
	writeFile(t, proj, "package-lock.json", lockfile("4.17.19"))
	var moved string
	for range 3 {
		r, data = status(lodash, "moved")
		if data.Check.Now == nil || data.Check.Now.ID == lodash || data.Check.Now.Version != "4.17.19" || !strings.Contains(r.text(), "Item "+lodash+" is not fixed: it is now item "+data.Check.Now.ID) {
			t.Fatalf("after an upgrade to a flagged version: %+v\n%s", data.Check, r.text())
		}
		moved = data.Check.Now.ID
		// A plain scan in between changes nothing about that.
		check(nil)
	}
	status(moved, "found")

	writeFile(t, proj, "package-lock.json", lockfile("4.17.21"))
	if r, _ := status(lodash, "gone"); !strings.Contains(r.text(), "Item "+lodash+" is no longer found: ") {
		t.Errorf("after the fix:\n%s", r.text())
	}
	status(moved, "gone")

	// The secret got its ID in this session, from the key this session
	// uses, so removing it shows.
	status(secret, "found")
	if err := os.Remove(filepath.Join(proj, "config", "app.env")); err != nil {
		t.Fatal(err)
	}
	status(secret, "gone")
	status(sg, "found")
	if _, data := check(nil); data.OpenItems != 1 {
		t.Errorf("open items after two fixes = %d, want 1", data.OpenItems)
	}

	for _, c := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"item": "nope"}, `is not an item's ID`},
		{map[string]any{"min_severity": "urgent"}, `Unknown severity "urgent"`},
		{map[string]any{"dir": "/"}, `Unknown argument "dir"`},
	} {
		if r := callOne(t, s, "hejnal_code_scan", c.args); !r.IsError || !strings.Contains(r.text(), c.want) {
			t.Errorf("%v: %+v, want an error containing %q", c.args, r, c.want)
		}
	}

	// A check saves nothing but the feed cache.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "cache" {
			t.Errorf("a check wrote %s to the state directory", e.Name())
		}
	}
	if !strings.Contains(l.String(), "mcp: code scan of shop started") {
		t.Errorf("the scan was not logged:\n%s", l.String())
	}
}

func strconvQuote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// A saved scan tells where an item was found, and its key keeps a secret's
// ID, so an item from the fix list can be checked in a new session.
func TestCodeScanToolSavedItem(t *testing.T) {
	dir := t.TempDir()
	proj, stateDir := filepath.Join(dir, "shop"), filepath.Join(dir, "state")
	writeFile(t, proj, "package-lock.json", lockfile("4.17.20"))
	writeFile(t, proj, "config/app.env", "STRIPE_KEY="+stripeKey+"\n")
	s, _ := codeServer(t, stateDir, proj)
	store := state.Store{Dir: stateDir}
	key, err := store.LeakKey()
	if err != nil {
		t.Fatal(err)
	}
	scan, err := s.engine.ScanCode(t.Context(), engine.CodeRequest{Project: "shop", Dirs: []string{proj}, FingerprintKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCodeScan(scan); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, it := range items(groupsOf(scan)) {
		ids[string(it.Kind)] = it.ID
	}

	status := func(s *Server, id string) *itemCheck {
		t.Helper()
		r := callOne(t, s, "hejnal_code_scan", map[string]any{"item": id})
		if r.IsError {
			t.Fatalf("item %s: %s", id, r.text())
		}
		return structured[codeScanData](t, r).Check
	}
	if c := status(s, ids["secret"]); c.Status != "found" {
		t.Errorf("the saved secret: %+v", c)
	}
	writeFile(t, proj, "package-lock.json", lockfile("4.17.21"))
	if err := os.Remove(filepath.Join(proj, "config", "app.env")); err != nil {
		t.Fatal(err)
	}
	// A new session knows the items from the state directory alone.
	s, _ = codeServer(t, stateDir, proj)
	if c := status(s, ids["dependency"]); c.Status != "gone" || c.Item == nil || c.Item.Version != "4.17.20" {
		t.Errorf("the saved dependency after the fix: %+v", c)
	}
	if c := status(s, ids["secret"]); c.Status != "gone" {
		t.Errorf("the saved secret after the fix: %+v", c)
	}

	// Another project's directory finds nothing, and that is no fix.
	other := filepath.Join(dir, "other")
	writeFile(t, other, "README.md", "nothing here\n")
	s, _ = codeServer(t, stateDir, other)
	if c := status(s, ids["dependency"]); c.Status != "unknown" || !strings.Contains(c.Why, `project "shop"`) {
		t.Errorf("the item checked in another project: %+v", c)
	}
}

func TestCodeScanToolNotOffered(t *testing.T) {
	dir := t.TempDir()
	l := &logs{}
	for _, cfg := range []Config{
		{Store: writeState(t, dir)},
		{Store: state.Store{Dir: dir}, Code: engine.CodeRequest{Dirs: []string{dir}}, Logf: l.logf},
	} {
		s := NewServer(cfg)
		if names, _ := toolNames(t, s); slices.Contains(names, "hejnal_code_scan") {
			t.Errorf("hejnal_code_scan offered with %+v", cfg)
		}
		resps := exchange(t, s, toolCall(1, "hejnal_code_scan", nil))
		if resps[0].Error == nil || resps[0].Error.Code != codeInvalidParams || !strings.Contains(resps[0].Error.Message, "not started with a source directory") {
			t.Errorf("calling hejnal_code_scan anyway: %+v", resps[0])
		}
	}
	if !strings.Contains(l.String(), "hejnal_code_scan is not offered") {
		t.Errorf("the missing engine was not logged:\n%s", l.String())
	}
}

// liveSite is a local WordPress site whose PHP header can be taken away,
// as an upgrade that hides the version would.
type liveSite struct {
	*httptest.Server
	noPHP atomic.Bool
	paths chan string
}

func newLiveSite(t *testing.T) *liveSite {
	t.Helper()
	ls := &liveSite{paths: make(chan string, 256)}
	ls.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case ls.paths <- r.URL.Path:
		default:
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !ls.noPHP.Load() {
			w.Header().Set("X-Powered-By", "PHP/8.3.12")
		}
		io.WriteString(w, `<html><head><title>Sklep</title><meta name="generator" content="WordPress 6.8.1"></head></html>`)
	}))
	t.Cleanup(ls.Close)
	return ls
}

func (ls *liveSite) asked() []string {
	var out []string
	for {
		select {
		case p := <-ls.paths:
			out = append(out, p)
		default:
			return out
		}
	}
}

func TestLiveCheckTool(t *testing.T) {
	site := newLiveSite(t)
	dir := t.TempDir()
	// The state directory lists items of other systems.
	writeState(t, dir)
	e := newEngine(t, dir, kevSample)
	l := &logs{}
	s := NewServer(Config{Engine: e, Scope: siteScope(t, site.URL), AllowRuns: true, Logf: l.logf})

	names, tools := toolNames(t, s)
	if n := len(names); n < 2 || names[n-2] != "hejnal_live_check" || names[n-1] != "hejnal_run" {
		t.Fatalf("tools = %v", names)
	}
	tl := tools["hejnal_live_check"]
	if a, _ := tl["annotations"].(map[string]any); a["readOnlyHint"] != false || a["openWorldHint"] != true || a["destructiveHint"] != false {
		t.Errorf("annotations = %v", tl["annotations"])
	}
	schema, _ := tl["inputSchema"].(map[string]any)
	if req, _ := schema["required"].([]any); len(req) != 1 || req[0] != "url" || schema["additionalProperties"] != false {
		t.Errorf("inputSchema = %v", schema)
	}
	if d, _ := tl["description"].(string); !strings.Contains(d, "/.git/HEAD") || !strings.Contains(d, "outside the scope is refused") {
		t.Errorf("description = %q", d)
	}

	shown := site.URL
	r := callOne(t, s, "hejnal_live_check", map[string]any{"url": site.URL + "/shop/cart"})
	for _, want := range []string{
		"Checked " + shown + `: status 200, title "Sklep".`,
		"Products: ", "PHP 8.3.12", "WordPress 6.8.1",
		`not at "/shop/cart"`,
		"Open items: 2.",
		"call hejnal_live_check with the same url and item set to its ID",
		"Nothing was saved",
	} {
		if r.IsError || !strings.Contains(r.text(), want) {
			t.Errorf("the check's text is missing %q:\n%s", want, r.text())
		}
	}
	data := structured[liveData](t, r)
	if data.Address != shown || data.Status != 200 || data.Title != "Sklep" || data.OpenItems != 2 || len(data.Items) != 2 || data.Check != nil {
		t.Fatalf("structured check = %+v", data)
	}
	if asked := site.asked(); !slices.Contains(asked, "/.git/HEAD") || slices.Contains(asked, "/shop/cart") {
		t.Errorf("paths asked for = %v", asked)
	}
	ids := map[string]string{}
	for _, it := range data.Items {
		ids[it.Technology] = it.ID
		if it.Host != "127.0.0.1" || it.Todo == "" || len(it.Places) == 0 {
			t.Errorf("item %+v", it)
		}
	}
	php, wp := ids["PHP"], ids["WordPress"]
	if php == "" || wp == "" {
		t.Fatalf("items = %+v", data.Items)
	}

	status := func(args map[string]any, want string) (toolResponse, *itemCheck) {
		t.Helper()
		r := callOne(t, s, "hejnal_live_check", args)
		if r.IsError {
			t.Fatalf("hejnal_live_check %v failed: %s", args, r.text())
		}
		c := structured[liveData](t, r).Check
		if c == nil || c.Status != want {
			t.Fatalf("%v: check = %+v, want status %s\n%s", args, c, want, r.text())
		}
		return r, c
	}
	if r, _ := status(map[string]any{"url": site.URL, "item": php}, "found"); !strings.Contains(r.text(), "Item "+php+" is still found: ") {
		t.Errorf("while PHP shows:\n%s", r.text())
	}
	site.noPHP.Store(true)
	if r, _ := status(map[string]any{"url": site.URL, "item": php, "wait_seconds": 1}, "gone"); !strings.Contains(r.text(), "Item "+php+" is no longer found: ") {
		t.Errorf("after the fix:\n%s", r.text())
	}
	status(map[string]any{"url": site.URL, "item": wp}, "found")
	status(map[string]any{"url": site.URL, "item": "00000000"}, "not_found")

	// An item of another system, known from the last run, is not told
	// gone by a look at this one.
	saved, err := engine.Known(e.Store())
	if err != nil || len(saved) == 0 {
		t.Fatalf("saved findings: %d, %v", len(saved), err)
	}
	elsewhere := items(groupsOfFindings(saved))[0]
	if _, c := status(map[string]any{"url": site.URL, "item": elsewhere.ID}, "unknown"); !strings.Contains(c.Why, "which this check did not look at") {
		t.Errorf("an item of another system: %+v", c)
	}

	// Nothing was saved: the state directory still holds the last run.
	if after, err := engine.Known(e.Store()); err != nil || len(after) != len(saved) {
		t.Errorf("saved findings after the checks: %d, %v, want %d", len(after), err, len(saved))
	}
	if !strings.Contains(l.String(), "mcp: live check of "+shown+" started") {
		t.Errorf("the check was not logged:\n%s", l.String())
	}
}

func TestLiveCheckToolRefusals(t *testing.T) {
	site := newLiveSite(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	e := newEngine(t, t.TempDir(), kevSample)

	s := NewServer(Config{Engine: e, Scope: siteScope(t, site.URL), AllowRuns: true})
	for _, c := range []struct {
		args map[string]any
		want string
	}{
		{nil, "Give the address to check as url"},
		{map[string]any{"url": "https://elsewhere.example"}, "Not checked: elsewhere.example is not in the scope"},
		{map[string]any{"url": "http://127.0.0.1:9"}, "Not checked: http://127.0.0.1:9: port 9 is not among the ports in the scope"},
		{map[string]any{"url": "https://anna:hunter2@127.0.0.1"}, "Cannot check that address: the address for 127.0.0.1 holds a user name or password"},
		{map[string]any{"url": "ftp://127.0.0.1"}, "only http and https"},
		{map[string]any{"url": site.URL, "wait_seconds": 301}, "Set wait_seconds between 0 and 300"},
		{map[string]any{"url": site.URL, "wait_seconds": -1}, "Set wait_seconds between 0 and 300"},
		{map[string]any{"url": site.URL, "item": "xyz"}, "is not an item's ID"},
		{map[string]any{"url": site.URL, "checks": false}, `Unknown argument "checks"`},
	} {
		r := callOne(t, s, "hejnal_live_check", c.args)
		if !r.IsError || !strings.Contains(r.text(), c.want) {
			t.Errorf("%v: %+v, want an error containing %q", c.args, r, c.want)
		}
		if strings.Contains(r.text(), "hunter2") {
			t.Errorf("the refusal repeats a password: %s", r.text())
		}
	}
	if asked := site.asked(); len(asked) != 0 {
		t.Errorf("a refused check contacted the site: %v", asked)
	}

	// Nothing answers: an error, not an empty result that reads as clean.
	s = NewServer(Config{Engine: e, Scope: siteScope(t, closedURL), AllowRuns: true})
	if r := callOne(t, s, "hejnal_live_check", map[string]any{"url": closedURL}); !r.IsError || !strings.Contains(r.text(), "Nothing to check: ") || !strings.Contains(r.text(), "wait_seconds") {
		t.Errorf("a system that is down: %+v", r)
	}

	// Without permission to run, the tool is not there.
	s = NewServer(Config{Engine: e, Scope: siteScope(t, site.URL)})
	if names, _ := toolNames(t, s); slices.Contains(names, "hejnal_live_check") {
		t.Errorf("hejnal_live_check offered without AllowRuns: %v", names)
	}
	resps := exchange(t, s, toolCall(1, "hejnal_live_check", map[string]any{"url": site.URL}))
	if resps[0].Error == nil || !strings.Contains(resps[0].Error.Message, "hejnal_live_check is not available: this server does not allow runs") {
		t.Errorf("calling hejnal_live_check anyway: %+v", resps[0])
	}
	if asked := site.asked(); len(asked) != 0 {
		t.Errorf("the tool that is not offered contacted the site: %v", asked)
	}
}

func TestInstructionsNameTheFixLoop(t *testing.T) {
	dir := t.TempDir()
	e := newEngine(t, dir, kevSample)
	plain := NewServer(Config{Store: writeState(t, t.TempDir())}).instructions()
	if strings.Contains(plain, "hejnal_code_scan") || strings.Contains(plain, "hejnal_live_check") || strings.Contains(plain, "status is gone") {
		t.Errorf("instructions name tools that are not offered:\n%s", plain)
	}
	code := NewServer(Config{Engine: e, Code: engine.CodeRequest{Dirs: []string{dir}}}).instructions()
	if !strings.Contains(code, "hejnal_code_scan") || strings.Contains(code, "hejnal_live_check") || !strings.Contains(code, "only when the status is gone") {
		t.Errorf("instructions with a source directory:\n%s", code)
	}
	runs := NewServer(Config{Engine: e, Scope: siteScope(t, "http://127.0.0.1:1"), AllowRuns: true}).instructions()
	if !strings.Contains(runs, "hejnal_live_check") || strings.Contains(runs, "hejnal_code_scan") || !strings.Contains(runs, "only when the status is gone") {
		t.Errorf("instructions with runs allowed:\n%s", runs)
	}
}

func groupsOf(scan *state.CodeScan) []match.Group { return groupsOfFindings(scan.Findings) }

func groupsOfFindings(fs []match.Finding) []match.Group { return match.Groups(match.Active(fs)) }
