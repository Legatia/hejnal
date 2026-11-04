package api

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// acceptGroup accepts the open findings of the item with the given key.
func acceptGroup(t *testing.T, key, until, reason string) match.Acceptance {
	t.Helper()
	for _, g := range match.Groups(fixtureFindings()) {
		if g.Key != key {
			continue
		}
		a := match.Acceptance{Item: g.ID(), Key: g.Key, Reason: reason, By: "Anna Nowak", AcceptedAt: testNow, Until: until}
		for _, f := range match.Active(g.Findings) {
			a.Findings = append(a.Findings, f.Key)
		}
		return a
	}
	t.Fatalf("no item %s", key)
	return match.Acceptance{}
}

func TestAcceptedItems(t *testing.T) {
	dir := t.TempDir()
	store := writeState(t, dir)
	const wpKey, tlsKey = "kev|shop.example.com|443|wordpress", "tls-expired|mail.example.com|443"
	// The WordPress item is accepted; the certificate's acceptance ended
	// yesterday.
	if err := store.SaveAccepted([]match.Acceptance{
		acceptGroup(t, wpKey, "2027-02-02", "Version 6.8.3 has the fixes"),
		acceptGroup(t, tlsKey, "2026-11-03", "Renewed by the hosting company"),
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, state.AcceptedFile))
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := newAPI(t, Config{Store: store})

	_, _, body := do(t, srv, http.MethodGet, "/v1/findings", testToken, nil)
	for _, f := range decode[findingsResponse](t, body).Findings {
		switch {
		case f.Key == "kev|shop.example.com|443|CVE-2026-119977" || f.Key == "kev|shop.example.com|443|CVE-2026-87902":
			if f.Accepted == nil || f.Accepted.Reason != "Version 6.8.3 has the fixes" || f.Accepted.Until != "2027-02-02" || f.Accepted.By != "Anna Nowak" {
				t.Errorf("%s is not marked accepted: %+v", f.Key, f.Accepted)
			}
		case f.Key == tlsKey:
			if f.Accepted != nil || f.AcceptanceExpired == nil || f.AcceptanceExpired.Until != "2026-11-03" {
				t.Errorf("the certificate is not marked as no longer accepted: %+v %+v", f.Accepted, f.AcceptanceExpired)
			}
		case f.Accepted != nil:
			t.Errorf("%s is marked accepted", f.Key)
		}
	}
	raw := decode[map[string]any](t, body)
	first, _ := raw["findings"].([]any)[0].(map[string]any)
	if acc, ok := first["accepted"].(map[string]any); !ok || acc["reason"] != "Version 6.8.3 has the fixes" || acc["until"] != "2027-02-02" {
		t.Errorf("findings JSON does not mark the accepted finding: %v", first)
	}

	_, _, body = do(t, srv, http.MethodGet, "/v1/groups", testToken, nil)
	got := decode[groupsResponse](t, body)
	var open []string
	for _, g := range got.Groups {
		open = append(open, g.Key)
		if g.ID != match.ItemID(g.Key) || g.Accepted != nil {
			t.Errorf("open item %+v", g)
		}
	}
	if !slices.Equal(open, []string{tlsKey, "admin-exposed|10.0.0.5|8080|jenkins", "kev|10.0.0.5|8080|jenkins"}) {
		t.Errorf("open items = %v", open)
	}
	if got.Counts != (severityCounts{High: 1, Medium: 2}) || got.Groups[0].AcceptanceExpired == nil {
		t.Errorf("counts %+v, certificate item %+v", got.Counts, got.Groups[0])
	}
	if len(got.AcceptedGroups) != 1 {
		t.Fatalf("accepted items = %+v", got.AcceptedGroups)
	}
	if wp := got.AcceptedGroups[0]; wp.ID != match.ItemID(wpKey) || wp.Accepted == nil || wp.Accepted.Reason != "Version 6.8.3 has the fixes" ||
		wp.Accepted.Until != "2027-02-02" || !slices.Equal(wp.CVEs, []string{"CVE-2026-119977", "CVE-2026-87902"}) {
		t.Errorf("accepted WordPress item = %+v", wp)
	}
	_, _, body = do(t, srv, http.MethodGet, "/v1/groups?min_severity=critical", testToken, nil)
	if got := decode[groupsResponse](t, body); len(got.Groups) != 0 || len(got.AcceptedGroups) != 1 {
		t.Errorf("min_severity=critical: %s", body)
	}

	// Accepted findings are not new.
	_, _, body = do(t, srv, http.MethodGet, "/v1/changes", testToken, nil)
	for _, f := range decode[changesResponse](t, body).Added {
		if strings.HasPrefix(f.Key, "kev|shop.example.com") {
			t.Errorf("accepted finding %s counts as new", f.Key)
		}
	}
	_, _, body = do(t, srv, http.MethodGet, "/v1/reports/fixlist", testToken, nil)
	if !strings.Contains(string(body), "## Accepted") || !strings.Contains(string(body), "`"+match.ItemID(wpKey)+"` WordPress on shop.example.com:443") {
		t.Errorf("fix list:\n%s", body)
	}

	// The API cannot accept or change acceptances.
	for _, path := range []string{"/v1/accepted", "/v1/groups"} {
		if status, _, _ := do(t, srv, http.MethodPost, path, testToken, strings.NewReader(`{"item": "x"}`)); status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: %d", path, status)
		}
	}
	if now, err := os.ReadFile(filepath.Join(dir, state.AcceptedFile)); err != nil || string(now) != string(saved) {
		t.Errorf("the API changed %s: %v", state.AcceptedFile, err)
	}

	// A broken file of acceptances is a server error, explained in the log.
	if err := os.WriteFile(filepath.Join(dir, state.AcceptedFile), []byte(`{"accepted": [{"item": 1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, logs := newAPI(t, Config{Store: store})
	status, _, body := do(t, srv, http.MethodGet, "/v1/findings", testToken, nil)
	if msg := errorText(t, body); status != http.StatusInternalServerError || !strings.Contains(msg, "accepted items") || strings.Contains(msg, dir) {
		t.Errorf("broken acceptances: %d %q", status, msg)
	}
	if !strings.Contains(logs.String(), state.AcceptedFile) {
		t.Errorf("the broken file was not logged:\n%s", logs.String())
	}
}
