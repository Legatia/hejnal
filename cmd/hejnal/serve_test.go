package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeNeedsAToken(t *testing.T) {
	h := newHarness(t)
	for _, token := range []string{"", "too-short"} {
		t.Setenv("HEJNAL_API_TOKEN", token)
		code, _, errOut := h.run("serve", "-state", h.state)
		if code != exitError || !strings.Contains(errOut, "HEJNAL_API_TOKEN") {
			t.Errorf("token %q: code %d, stderr %q", token, code, errOut)
		}
	}
}

func TestServeAllowRunsNeedsAScope(t *testing.T) {
	h := newHarness(t)
	t.Setenv("HEJNAL_API_TOKEN", strings.Repeat("a1", 20))
	code, _, errOut := h.run("serve", "-allow-runs", "-scope", h.dir+"/missing.json", "-state", h.state)
	if code != exitError || !strings.Contains(errOut, "not found") {
		t.Errorf("code %d, stderr %q", code, errOut)
	}
}

// TestMCPOverStdio drives `hejnal mcp` with a scripted assistant after a real
// run, the way an MCP client starts it.
func TestMCPOverStdio(t *testing.T) {
	h := newHarness(t)
	if code, _, errOut := h.run(h.runArgs()...); code != exitOK {
		t.Fatalf("run: code %d\n%s", code, errOut)
	}
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hejnal_fix_list","arguments":{"lang":"pl"}}}`,
	}
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.now = func() time.Time { return testNow }
	a.stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if code := a.run(ctx, []string{"mcp", "-state", h.state}); code != exitOK {
		t.Fatalf("mcp: code %d\n%s", code, errOut.String())
	}

	responses := map[float64]map[string]any{}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			t.Fatalf("stdout carries something other than JSON-RPC: %q", sc.Text())
		}
		id, _ := msg["id"].(float64)
		responses[id] = msg
	}
	if len(responses) != 3 {
		t.Fatalf("want 3 responses, got %d: %s", len(responses), out.String())
	}
	tools, _ := json.Marshal(responses[2])
	if !strings.Contains(string(tools), "hejnal_fix_list") || strings.Contains(string(tools), "hejnal_run") {
		t.Errorf("tools/list without -allow-runs: %s", tools)
	}
	fix, _ := json.Marshal(responses[3])
	if !strings.Contains(string(fix), "Lista poprawek Hejnal") {
		t.Errorf("fix list tool: %s", fix)
	}
}

// With -code, an assistant can check a source directory and ask whether an
// item is still found there.
func TestMCPCodeOverStdio(t *testing.T) {
	dir := t.TempDir()
	proj, stateDir := filepath.Join(dir, "shop"), filepath.Join(dir, "state")
	writeFiles(t, proj, map[string]string{"package-lock.json": lockfile("4.17.20")})
	osvSrv := fakeOSV(t)
	session := func(requests ...string) map[float64]map[string]any {
		t.Helper()
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut)
		a.now = func() time.Time { return testNow }
		a.osvURL = osvSrv.URL
		a.stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if code := a.run(ctx, []string{"mcp", "-state", stateDir, "-kev-file", kevSample, "-no-epss", "-no-nvd", "-code", proj}); code != exitOK {
			t.Fatalf("mcp -code: code %d\n%s", code, errOut.String())
		}
		responses := map[float64]map[string]any{}
		sc := bufio.NewScanner(&out)
		sc.Buffer(make([]byte, 1<<20), 4<<20)
		for sc.Scan() {
			var msg map[string]any
			if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
				t.Fatalf("stdout carries something other than JSON-RPC: %q", sc.Text())
			}
			id, _ := msg["id"].(float64)
			responses[id] = msg
		}
		return responses
	}
	check := func(item string) string {
		args := `{}`
		if item != "" {
			args = `{"item":"` + item + `"}`
		}
		return `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hejnal_code_scan","arguments":` + args + `}}`
	}
	structured := func(msg map[string]any) map[string]any {
		t.Helper()
		res, _ := msg["result"].(map[string]any)
		data, _ := res["structuredContent"].(map[string]any)
		if data == nil || res["isError"] == true {
			t.Fatalf("hejnal_code_scan: %v", msg)
		}
		return data
	}

	got := session(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, check(""))
	tools, _ := json.Marshal(got[2])
	if !strings.Contains(string(tools), "hejnal_code_scan") || strings.Contains(string(tools), "hejnal_live_check") || !strings.Contains(string(tools), `project \"shop\"`) {
		t.Errorf("tools/list with -code: %s", tools)
	}
	data := structured(got[3])
	list, _ := data["items"].([]any)
	if data["project"] != "shop" || len(list) != 1 {
		t.Fatalf("code scan = %v", data)
	}
	first, _ := list[0].(map[string]any)
	id, _ := first["id"].(string)
	if first["fixedIn"] != "4.17.21" || id == "" {
		t.Fatalf("item = %v", first)
	}

	// A session that found the item still finds it.
	got = session(check(""), strings.Replace(check(id), `"id":3`, `"id":4`, 1))
	if c, _ := structured(got[4])["check"].(map[string]any); c["status"] != "found" {
		t.Errorf("while the package is there: %v", c)
	}
	// Nothing was saved, so a new session after the fix has no record of
	// the item: it says so, and does not call it fixed.
	writeFiles(t, proj, map[string]string{"package-lock.json": lockfile("4.17.21")})
	got = session(check(id))
	if c, _ := structured(got[3])["check"].(map[string]any); c["status"] != "not_found" {
		t.Errorf("a new session after the fix: %v", c)
	}

	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.osvURL = osvSrv.URL
	a.stdin = strings.NewReader("")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"mcp", "-state", stateDir, "-project", "shop"}, "name it with -code"},
		{[]string{"mcp", "-state", stateDir, "-exclude", "vendor"}, "name it with -code"},
		{[]string{"mcp", "-state", stateDir, "-offline", "-code", proj}, "run without -offline"},
		{[]string{"mcp", "-state", stateDir, "-code", filepath.Join(dir, "missing")}, "is not a directory"},
	} {
		errOut.Reset()
		if code := a.run(context.Background(), c.args); code != exitError || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("%v: code %d, want an error containing %q\n%s", c.args, code, c.want, errOut.String())
		}
	}
}

func lockfile(version string) string {
	return `{"packages":{"node_modules/lodash":{"version":"` + version + `"},"node_modules/react":{"version":"18.2.0"}}}`
}
