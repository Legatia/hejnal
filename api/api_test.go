package api

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

func TestNewHandlerChecksConfig(t *testing.T) {
	dir := t.TempDir()
	e := newEngine(t, dir, kevSample)
	store := state.Store{Dir: dir}
	scopeFn := func() (*scope.Scope, error) { return nil, nil }
	bad := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no token", Config{Store: store}, "at least 32 characters"},
		{"short token", Config{Store: store, Token: testToken[:31]}, "at least 32 characters"},
		{"token with a space", Config{Store: store, Token: testToken[:16] + " " + testToken[16:]}, "printable ASCII"},
		{"token with a newline", Config{Store: store, Token: testToken + "\n"}, "printable ASCII"},
		{"runs without an engine", Config{Store: store, Token: testToken, AllowRuns: true, Scope: scopeFn}, "engine and a scope"},
		{"runs without a scope", Config{Token: testToken, AllowRuns: true, Engine: e}, "engine and a scope"},
		{"no state directory", Config{Token: testToken}, "Store.Dir is required"},
		{"another state directory", Config{Store: state.Store{Dir: t.TempDir()}, Token: testToken, Engine: e}, "not the engine's state directory"},
	}
	for _, c := range bad {
		if _, err := NewHandler(c.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
	good := []Config{
		{Store: store, Token: testToken},
		{Token: testToken, Engine: e},
		{Store: state.Store{Dir: filepath.Join(dir, ".")}, Token: testToken, Engine: e, Scope: scopeFn, AllowRuns: true},
	}
	for i, cfg := range good {
		if _, err := NewHandler(cfg); err != nil {
			t.Errorf("config %d: %v", i, err)
		}
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	srv, _ := newAPI(t, Config{Store: state.Store{Dir: t.TempDir()}})
	status, hdr, body := do(t, srv, http.MethodGet, "/v1/health", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	got := decode[map[string]any](t, body)
	if len(got) != 2 || got["status"] != "ok" || got["version"] != version.Version {
		t.Errorf("health = %s, want only status and version", body)
	}
	checkCommonHeaders(t, hdr)
	if ct := hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	status, hdr, body = do(t, srv, http.MethodPost, "/v1/health", "", nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != "GET, HEAD" {
		t.Errorf("POST /v1/health: %d, Allow %q", status, hdr.Get("Allow"))
	}
	errorText(t, body)
}

func checkCommonHeaders(t *testing.T, hdr http.Header) {
	t.Helper()
	if v := hdr.Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", v)
	}
	if v := hdr.Get("Cache-Control"); v != "no-store" {
		t.Errorf("Cache-Control = %q", v)
	}
}

func TestAuth(t *testing.T) {
	srv, logs := newAPI(t, Config{Store: writeState(t, t.TempDir())})
	const wrong = "not-the-right-token-but-long-enough-1234"
	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong", "Bearer " + wrong, http.StatusUnauthorized},
		{"prefix of the token", "Bearer " + testToken[:31], http.StatusUnauthorized},
		{"token plus more", "Bearer " + testToken + "0", http.StatusUnauthorized},
		{"no token after the scheme", "Bearer ", http.StatusUnauthorized},
		{"basic auth", "Basic " + testToken, http.StatusUnauthorized},
		{"bare token", testToken, http.StatusUnauthorized},
		{"right", "Bearer " + testToken, http.StatusOK},
		{"scheme in lower case", "bearer " + testToken, http.StatusOK},
	}
	refused := 0
	for _, c := range cases {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/findings", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", c.name, resp.StatusCode, c.want)
		}
		checkCommonHeaders(t, resp.Header)
		if c.want == http.StatusUnauthorized {
			refused++
			if v := resp.Header.Get("WWW-Authenticate"); v != "Bearer" {
				t.Errorf("%s: WWW-Authenticate = %q", c.name, v)
			}
		}
	}
	log := logs.String()
	if n := strings.Count(log, "api: refused GET \"/v1/findings\""); n != refused {
		t.Errorf("logged %d refusals, want %d:\n%s", n, refused, log)
	}
	if !strings.Contains(log, "wrong token") || !strings.Contains(log, "no bearer token") {
		t.Errorf("refusals do not say why:\n%s", log)
	}
	if strings.Contains(log, wrong) || strings.Contains(log, testToken[:8]) {
		t.Errorf("a token was logged:\n%s", log)
	}

	// Errors are JSON, and unknown paths and methods need the token too.
	status, _, body := do(t, srv, http.MethodGet, "/v1/findings", "", nil)
	if !strings.Contains(errorText(t, body), "Authorization: Bearer") || status != http.StatusUnauthorized {
		t.Errorf("401 body: %s", body)
	}
	for _, path := range []string{"/v1/nope", "/v1/findings/", "/"} {
		if status, _, _ := do(t, srv, http.MethodGet, path, "", nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: %d", path, status)
		}
		status, _, body := do(t, srv, http.MethodGet, path, testToken, nil)
		if status != http.StatusNotFound || !strings.Contains(errorText(t, body), "/v1/findings") {
			t.Errorf("GET %s: %d %s", path, status, body)
		}
	}
	if status, _, _ := do(t, srv, http.MethodDelete, "/v1/findings", "", nil); status != http.StatusUnauthorized {
		t.Errorf("DELETE without a token: %d", status)
	}
	status, hdr, body := do(t, srv, http.MethodDelete, "/v1/findings", testToken, nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != "GET, HEAD" {
		t.Errorf("DELETE /v1/findings: %d, Allow %q", status, hdr.Get("Allow"))
	}
	errorText(t, body)
	status, hdr, _ = do(t, srv, http.MethodGet, "/v1/runs", testToken, nil)
	if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != "POST" {
		t.Errorf("GET /v1/runs: %d, Allow %q", status, hdr.Get("Allow"))
	}
	status, hdr, body = do(t, srv, http.MethodHead, "/v1/findings", testToken, nil)
	if status != http.StatusOK || len(body) != 0 || hdr.Get("Content-Type") != "application/json" {
		t.Errorf("HEAD /v1/findings: %d %q %q", status, hdr.Get("Content-Type"), body)
	}
}

func TestNotFoundBeforeFirstRun(t *testing.T) {
	paths := map[string]string{
		"/v1/findings":        "no findings yet",
		"/v1/groups":          "no findings yet",
		"/v1/changes":         "no findings yet",
		"/v1/reports/fixlist": "no findings yet",
		"/v1/reports/nis2":    "no findings yet",
		"/v1/inventory":       "no inventory yet",
	}
	srv, _ := newAPI(t, Config{Store: state.Store{Dir: t.TempDir()}})
	for path, want := range paths {
		status, hdr, body := do(t, srv, http.MethodGet, path, testToken, nil)
		msg := errorText(t, body)
		if status != http.StatusNotFound || !strings.Contains(msg, want) || !strings.Contains(msg, "hejnal run") {
			t.Errorf("%s: %d %q", path, status, msg)
		}
		if strings.Contains(msg, "POST /v1/runs") {
			t.Errorf("%s suggests starting a run on a server that does not allow it: %q", path, msg)
		}
		checkCommonHeaders(t, hdr)
	}

	// When runs are allowed, the message says how to start one.
	dir := t.TempDir()
	srv, _ = newAPI(t, Config{Engine: newEngine(t, dir, kevSample), Scope: siteScope(t, "http://127.0.0.1:1"), AllowRuns: true})
	for path := range paths {
		_, _, body := do(t, srv, http.MethodGet, path, testToken, nil)
		if msg := errorText(t, body); !strings.Contains(msg, "POST /v1/runs") {
			t.Errorf("%s: %q", path, msg)
		}
	}
}

func TestFindingsFilters(t *testing.T) {
	srv, _ := newAPI(t, Config{Store: writeState(t, t.TempDir())})
	all := keys(fixtureFindings())
	cases := []struct {
		query string
		want  []string
	}{
		{"", all},
		{"?min_severity=none", all},
		{"?min_severity=", all},
		{"?min_severity=high", all[:3]},
		{"?min_severity=CRITICAL", all[:1]},
		{"?kind=kev", []string{all[0], all[1], all[4], all[5]}},
		{"?kind=TLS-Expired", []string{all[2]}},
		{"?kind=admin-exposed", []string{all[3]}},
		{"?kind=tls-expiring", nil},
		{"?host=SHOP.example.com.", []string{all[0], all[1], all[5]}},
		{"?host=%5B::ffff:10.0.0.5%5D", []string{all[3], all[4]}},
		{"?host=10.0.0.5&kind=kev&min_severity=medium", []string{all[4]}},
		{"?host=other.example.com", nil},
	}
	for _, c := range cases {
		status, _, body := do(t, srv, http.MethodGet, "/v1/findings"+c.query, testToken, nil)
		if status != http.StatusOK {
			t.Errorf("%s: status %d: %s", c.query, status, body)
			continue
		}
		got := decode[findingsResponse](t, body)
		if got.Findings == nil {
			t.Errorf("%s: findings is null, want a list", c.query)
		}
		if !slices.Equal(keys(got.Findings), c.want) && (len(c.want) > 0 || len(got.Findings) > 0) {
			t.Errorf("%s: got %v, want %v", c.query, keys(got.Findings), c.want)
		}
		if got.KEVVersion != "2026.11.03" || !got.GeneratedAt.Equal(testNow) || got.Organization != "Sklep Sp. z o.o." {
			t.Errorf("%s: metadata %+v", c.query, got)
		}
	}
	// The response carries the fields clients need.
	_, _, body := do(t, srv, http.MethodGet, "/v1/findings", testToken, nil)
	raw := decode[map[string]any](t, body)
	for _, k := range []string{"generatedAt", "kevVersion", "findings"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response has no %q: %s", k, body)
		}
	}

	bad := map[string]string{
		"?min_severity=urgent":   "unknown severity",
		"?kind=vuln":             "unknown kind",
		"?severity=high":         `unknown parameter "severity"`,
		"?host=a.example&host=b": "more than once",
		"?host=%zz":              "cannot read the query string",
	}
	for q, want := range bad {
		status, _, body := do(t, srv, http.MethodGet, "/v1/findings"+q, testToken, nil)
		if msg := errorText(t, body); status != http.StatusBadRequest || !strings.Contains(msg, want) {
			t.Errorf("%s: %d %q, want 400 mentioning %q", q, status, msg, want)
		}
	}
}

func TestGroups(t *testing.T) {
	srv, _ := newAPI(t, Config{Store: writeState(t, t.TempDir())})
	status, _, body := do(t, srv, http.MethodGet, "/v1/groups", testToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	got := decode[groupsResponse](t, body)
	if len(got.Groups) != 4 {
		t.Fatalf("got %d groups, want 4: %s", len(got.Groups), body)
	}
	wp := got.Groups[0]
	if wp.Kind != match.KindKEV || wp.Host != "shop.example.com" || wp.Port != 443 || wp.Technology != "WordPress" ||
		wp.Version != "6.8.1" || wp.Severity != match.Critical || wp.Score != 85 || wp.NewestDateAdded != "2026-11-03" || !wp.Forensics {
		t.Errorf("first group = %+v", wp)
	}
	// The flaw the version check rules out is not an item to fix.
	if !slices.Equal(wp.CVEs, []string{"CVE-2026-119977", "CVE-2026-87902"}) {
		t.Errorf("WordPress CVEs = %v", wp.CVEs)
	}
	if got.RuledOut != 1 {
		t.Errorf("ruledOut = %d, want 1", got.RuledOut)
	}
	tls := got.Groups[1]
	if tls.Kind != match.KindTLSExpired || tls.Expires == nil || tls.CVEs == nil || len(tls.CVEs) != 0 {
		t.Errorf("TLS group = %+v", tls)
	}
	if got.Counts != (severityCounts{Critical: 1, High: 1, Medium: 2}) {
		t.Errorf("counts = %+v", got.Counts)
	}

	_, _, body = do(t, srv, http.MethodGet, "/v1/groups?min_severity=high", testToken, nil)
	got = decode[groupsResponse](t, body)
	if len(got.Groups) != 2 || got.Counts != (severityCounts{Critical: 1, High: 1}) {
		t.Errorf("min_severity=high: %s", body)
	}
	_, _, body = do(t, srv, http.MethodGet, "/v1/groups?min_severity=critical", testToken, nil)
	if got = decode[groupsResponse](t, body); len(got.Groups) != 1 || got.Groups[0].Technology != "WordPress" {
		t.Errorf("min_severity=critical: %s", body)
	}
	for _, q := range []string{"?min_severity=bad", "?kind=kev"} {
		if status, _, body := do(t, srv, http.MethodGet, "/v1/groups"+q, testToken, nil); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", q, status, body)
		}
	}
}

func TestInventory(t *testing.T) {
	srv, _ := newAPI(t, Config{Store: writeState(t, t.TempDir())})
	status, _, body := do(t, srv, http.MethodGet, "/v1/inventory", testToken, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	inv := decode[inventory.Inventory](t, body)
	if inv.Organization != "Sklep Sp. z o.o." || len(inv.Assets) != 3 || inv.Assets[2].Services[0].Technologies[0].Name != "Jenkins" {
		t.Errorf("inventory = %s", body)
	}
	if status, _, _ := do(t, srv, http.MethodGet, "/v1/inventory?host=x", testToken, nil); status != http.StatusBadRequest {
		t.Errorf("unknown parameter: %d", status)
	}
}

func TestChangesDoNotMarkReported(t *testing.T) {
	store := writeState(t, t.TempDir())
	srv, _ := newAPI(t, Config{Store: store})
	all := keys(fixtureFindings())

	// Before anything was reported, everything not ruled out is new.
	for range 2 {
		status, _, body := do(t, srv, http.MethodGet, "/v1/changes", testToken, nil)
		if status != http.StatusOK {
			t.Fatalf("status %d: %s", status, body)
		}
		got := decode[changesResponse](t, body)
		if !got.First || !slices.Equal(keys(got.Added), all[:5]) || got.Resolved == nil || len(got.Resolved) != 0 {
			t.Errorf("first changes = %s", body)
		}
	}
	if snap, err := store.LoadReported(); snap != nil || err != nil {
		t.Fatalf("reading changes marked findings as reported: %v %v", snap, err)
	}

	// After a report, only the differences count.
	gone := match.Finding{Key: "kev|old.example.com|443|CVE-2021-41773", Kind: match.KindKEV, Host: "old.example.com", Port: 443, CVE: "CVE-2021-41773"}
	if err := store.SaveReported(&state.Snapshot{Findings: []match.Finding{fixtureFindings()[0], gone}}); err != nil {
		t.Fatal(err)
	}
	_, _, body := do(t, srv, http.MethodGet, "/v1/changes", testToken, nil)
	got := decode[changesResponse](t, body)
	if got.First || !slices.Equal(keys(got.Added), all[1:5]) || !slices.Equal(keys(got.Resolved), []string{gone.Key}) {
		t.Errorf("changes after a report = %s", body)
	}
	if status, _, _ := do(t, srv, http.MethodGet, "/v1/changes?since=yesterday", testToken, nil); status != http.StatusBadRequest {
		t.Errorf("unknown parameter: %d", status)
	}
}

func TestReports(t *testing.T) {
	srv, _ := newAPI(t, Config{Store: writeState(t, t.TempDir())})
	cases := []struct {
		path, lang string
		want       []string
	}{
		{"/v1/reports/fixlist", "en", []string{"# Hejnal fix list: Sklep Sp. z o.o.", "## Fix now (critical)", "CVE-2026-119977", "mail.example.com:443"}},
		{"/v1/reports/fixlist?lang=en", "en", []string{"# Hejnal fix list"}},
		{"/v1/reports/fixlist?lang=pl", "pl", []string{"# Lista poprawek Hejnal", "Napraw teraz (krytyczne)"}},
		{"/v1/reports/fixlist?lang=PL", "pl", []string{"# Lista poprawek Hejnal"}},
		{"/v1/reports/nis2", "en", []string{"# NIS2 early warning: draft", "CVE-2026-119977"}},
		{"/v1/reports/nis2?lang=pl", "pl", []string{"NIS2: wczesne ostrzeżenie", "CSIRT"}},
	}
	for _, c := range cases {
		status, hdr, body := do(t, srv, http.MethodGet, c.path, testToken, nil)
		if status != http.StatusOK {
			t.Errorf("%s: status %d: %s", c.path, status, body)
			continue
		}
		if ct := hdr.Get("Content-Type"); ct != "text/markdown; charset=utf-8" {
			t.Errorf("%s: Content-Type = %q", c.path, ct)
		}
		if l := hdr.Get("Content-Language"); l != c.lang {
			t.Errorf("%s: Content-Language = %q", c.path, l)
		}
		checkCommonHeaders(t, hdr)
		for _, w := range c.want {
			if !strings.Contains(string(body), w) {
				t.Errorf("%s is missing %q:\n%s", c.path, w, body)
			}
		}
	}
	for _, q := range []string{"/v1/reports/fixlist?lang=de", "/v1/reports/nis2?lang=english", "/v1/reports/fixlist?format=pdf"} {
		status, hdr, body := do(t, srv, http.MethodGet, q, testToken, nil)
		if status != http.StatusBadRequest || hdr.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q", q, status, hdr.Get("Content-Type"))
		}
		errorText(t, body)
	}
}

func TestBodyLimit(t *testing.T) {
	srv, _ := newAPI(t, Config{Store: writeState(t, t.TempDir())})
	big := strings.Repeat("x", maxBody+1)

	status, _, body := do(t, srv, http.MethodPost, "/v1/runs", testToken, strings.NewReader(big))
	if status != http.StatusRequestEntityTooLarge || !strings.Contains(errorText(t, body), "1 KiB") {
		t.Errorf("declared large body: %d %s", status, body)
	}
	// A chunked body declares no length, so the limit applies while reading.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/findings", struct{ *strings.Reader }{strings.NewReader(big)})
	req.Header.Set("Authorization", "Bearer "+testToken)
	if req.ContentLength != 0 {
		t.Fatalf("test body has a length: %d", req.ContentLength)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked large body: %d", resp.StatusCode)
	}
	// Large bodies are refused even without a token.
	if status, _, _ := do(t, srv, http.MethodGet, "/v1/findings", "", strings.NewReader(big)); status != http.StatusRequestEntityTooLarge {
		t.Errorf("large body without a token: %d", status)
	}
	if status, _, _ := do(t, srv, http.MethodGet, "/v1/findings", testToken, strings.NewReader(big[:maxBody])); status != http.StatusOK {
		t.Errorf("1 KiB body: %d", status)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		" Shop.Example.COM. ":    "shop.example.com",
		"[2001:DB8::1]":          "2001:db8::1",
		"2001:0db8:0000::0001":   "2001:db8::1",
		"::ffff:192.0.2.1":       "192.0.2.1",
		"fe80::1%eth0":           "fe80::1",
		"":                       "",
		"not an ip, not a name.": "not an ip, not a name",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// leakFindings are a secret found in two places, two breaches of one domain
// and an exposed environment file.
func leakFindings() []match.Finding {
	secret := match.Finding{Kind: match.KindSecret, Technology: "AWS access key", Fingerprint: "fp1", Evidence: "AKIA…WXYZ",
		Score: 80, Severity: match.High, Confidence: match.ConfidenceObserved}
	s1, s2 := secret, secret
	s1.Key, s1.File, s1.Line = "secret|config/app.env|12|fp1", "config/app.env", 12
	s2.Key, s2.File, s2.Line, s2.Commit = "secret|old/app.env|3|fp1", "old/app.env", 3, "0123456789abcdef0123"
	breach := match.Finding{Kind: match.KindBreach, Host: "example.com", Confidence: match.ConfidenceObserved}
	b1, b2 := breach, breach
	b1.Key, b1.Name, b1.BreachDate, b1.Accounts, b1.Passwords, b1.Score, b1.Severity = "breach|example.com|Canva", "Canva", "2019-05-24", 12, true, 60, match.Medium
	b2.Key, b2.Name, b2.BreachDate, b2.Accounts, b2.Score, b2.Severity = "breach|example.com|LinkedIn", "LinkedIn", "2012-05-05", 3, 55, match.Medium
	env := match.Finding{Key: "exposed-file|shop.example.com|443|env", Kind: match.KindExposedFile, Host: "shop.example.com", Port: 443,
		URL: "https://shop.example.com/.env", TechID: "env", Evidence: "4 variables, including DB_PASSWORD", Score: 90,
		Severity: match.Critical, Confidence: match.ConfidenceObserved}
	fs := []match.Finding{s1, s2, b1, b2, env}
	match.Sort(fs)
	return fs
}

func TestSecretsBreachesAndExposedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := (state.Store{Dir: dir}).SaveFindings(&state.Snapshot{Organization: "Org", GeneratedAt: testNow, Findings: leakFindings()}); err != nil {
		t.Fatal(err)
	}
	srv, _ := newAPI(t, Config{Store: state.Store{Dir: dir}})
	for q, want := range map[string]int{"?kind=secret": 2, "?kind=BREACH": 2, "?kind=exposed-file": 1, "?host=example.com": 2} {
		_, _, body := do(t, srv, http.MethodGet, "/v1/findings"+q, testToken, nil)
		if got := decode[findingsResponse](t, body); len(got.Findings) != want {
			t.Errorf("%s: %d findings, want %d", q, len(got.Findings), want)
		}
	}
	status, _, body := do(t, srv, http.MethodGet, "/v1/findings?kind=leak", testToken, nil)
	if msg := errorText(t, body); status != http.StatusBadRequest || !strings.Contains(msg, "admin-exposed, exposed-file, takeover, email, secret, breach, dependency or misconfig") {
		t.Errorf("unknown kind: %d %q", status, msg)
	}

	_, _, body = do(t, srv, http.MethodGet, "/v1/groups", testToken, nil)
	got := decode[groupsResponse](t, body)
	var keys []string
	for _, g := range got.Groups {
		keys = append(keys, g.Key)
	}
	// A secret is one item wherever it was found, and breaches of a domain
	// are one item.
	if !slices.Equal(keys, []string{"exposed-file|shop.example.com|443|env", "secret|fp1", "breach|example.com"}) {
		t.Fatalf("group keys = %v", keys)
	}
	if s := got.Groups[1]; s.Kind != match.KindSecret || s.Host != "" || s.Port != 0 || s.Technology != "AWS access key" || len(s.CVEs) != 0 {
		t.Errorf("secret item = %+v", s)
	}
	if b := got.Groups[2]; b.Host != "example.com" || b.Port != 0 || b.Severity != match.Medium {
		t.Errorf("breach item = %+v", b)
	}
	raw := decode[struct {
		Groups []map[string]any `json:"groups"`
	}](t, body)
	if raw.Groups[0]["key"] != "exposed-file|shop.example.com|443|env" {
		t.Errorf("groups carry no key: %s", body)
	}
}

func TestUnreadableStateIsAServerError(t *testing.T) {
	dir := t.TempDir()
	srv, logs := newAPI(t, Config{Store: writeState(t, dir)})
	if err := os.WriteFile(filepath.Join(dir, "reported.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, body := do(t, srv, http.MethodGet, "/v1/changes", testToken, nil)
	if msg := errorText(t, body); status != http.StatusInternalServerError || strings.Contains(msg, dir) {
		t.Errorf("unreadable report record: %d %q", status, msg)
	}
	for _, name := range []string{"findings.json", "inventory.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/v1/findings", "/v1/inventory", "/v1/reports/fixlist"} {
		status, _, body := do(t, srv, http.MethodGet, path, testToken, nil)
		// The details go to the log, not to the client.
		if msg := errorText(t, body); status != http.StatusInternalServerError || !strings.Contains(msg, "see the server log") || strings.Contains(msg, dir) {
			t.Errorf("%s: %d %q", path, status, msg)
		}
	}
	if log := logs.String(); !strings.Contains(log, "findings.json") || !strings.Contains(log, "inventory.json") || !strings.Contains(log, "reported.json") {
		t.Errorf("the unreadable files were not logged:\n%s", log)
	}
}
