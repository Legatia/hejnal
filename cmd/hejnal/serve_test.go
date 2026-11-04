package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
