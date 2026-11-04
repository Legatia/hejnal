package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

func TestInitializeNegotiatesVersion(t *testing.T) {
	l := &logs{}
	s := NewServer(Config{Store: state.Store{Dir: t.TempDir()}, Logf: l.logf})
	for _, c := range []struct{ asked, want string }{
		{"2025-06-18", "2025-06-18"},
		{"2025-03-26", "2025-03-26"},
		{"2024-11-05", "2024-11-05"},
		{"2099-01-01", "2025-06-18"},
		{"", "2025-06-18"},
	} {
		params := map[string]any{"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test-client", "version": "1.0"}}
		if c.asked != "" {
			params["protocolVersion"] = c.asked
		}
		resps := exchange(t, s, request(1, "initialize", params), notify("notifications/initialized", nil))
		if len(resps) != 1 || resps[0].Error != nil || string(resps[0].ID) != "1" {
			t.Fatalf("asked %q: responses %+v", c.asked, resps)
		}
		var res struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    json.RawMessage `json:"capabilities"`
			ServerInfo      map[string]any  `json:"serverInfo"`
			Instructions    string          `json:"instructions"`
		}
		if err := json.Unmarshal(resps[0].Result, &res); err != nil {
			t.Fatal(err)
		}
		if res.ProtocolVersion != c.want {
			t.Errorf("asked %q: got version %q, want %q", c.asked, res.ProtocolVersion, c.want)
		}
		if string(res.Capabilities) != `{"tools":{"listChanged":false}}` {
			t.Errorf("capabilities = %s", res.Capabilities)
		}
		if len(res.ServerInfo) != 2 || res.ServerInfo["name"] != "hejnal" || res.ServerInfo["version"] != version.Version {
			t.Errorf("serverInfo = %v", res.ServerInfo)
		}
		if !strings.Contains(res.Instructions, "hejnal_summary") || strings.Contains(res.Instructions, "hejnal_run") {
			t.Errorf("instructions = %q", res.Instructions)
		}
	}
	if !strings.Contains(l.String(), `client "test-client" "1.0" connected`) {
		t.Errorf("connection not logged:\n%s", l.String())
	}
}

func TestNotificationsGetNoResponse(t *testing.T) {
	s := NewServer(Config{Store: state.Store{Dir: t.TempDir()}})
	resps := exchange(t, s,
		notify("notifications/initialized", nil),
		notify("notifications/cancelled", map[string]any{"requestId": 99, "reason": "not running"}),
		notify("notifications/progress", map[string]any{"progressToken": 1, "progress": 1}),
		notify("tools/list", nil),
		notify("no/such/method", map[string]any{"x": 1}),
		`{"jsonrpc":"2.0","id":5,"result":{}}`,
		request(2, "ping", nil),
		request("three", "ping", map[string]any{}),
	)
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2: %+v", len(resps), resps)
	}
	for i, id := range []string{`2`, `"three"`} {
		if string(resps[i].ID) != id || string(resps[i].Result) != "{}" {
			t.Errorf("ping %s: id %s result %s", id, resps[i].ID, resps[i].Result)
		}
	}
}

func TestToolsList(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir)
	names := func(s *Server) ([]string, []map[string]any) {
		resps := exchange(t, s, request(1, "tools/list", nil))
		var res struct {
			Tools []map[string]any `json:"tools"`
		}
		if len(resps) != 1 || json.Unmarshal(resps[0].Result, &res) != nil {
			t.Fatalf("tools/list: %+v", resps)
		}
		var out []string
		for _, tl := range res.Tools {
			out = append(out, tl["name"].(string))
		}
		return out, res.Tools
	}
	readOnly := []string{"hejnal_summary", "hejnal_fix_list", "hejnal_findings", "hejnal_inventory", "hejnal_nis2_draft"}

	got, tools := names(NewServer(Config{Store: state.Store{Dir: dir}}))
	if !slices.Equal(got, readOnly) {
		t.Errorf("tools = %v, want %v", got, readOnly)
	}
	for _, tl := range tools {
		name := tl["name"]
		if d, _ := tl["description"].(string); len(d) < 40 {
			t.Errorf("%s: description %q", name, d)
		}
		schema, _ := tl["inputSchema"].(map[string]any)
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Errorf("%s: inputSchema = %v", name, schema)
		}
		if _, ok := schema["properties"].(map[string]any); !ok {
			t.Errorf("%s: inputSchema has no properties object", name)
		}
		if a, _ := tl["annotations"].(map[string]any); a["readOnlyHint"] != true {
			t.Errorf("%s: annotations = %v", name, a)
		}
	}
	findings := tools[2]["inputSchema"].(map[string]any)["properties"].(map[string]any)
	for _, p := range []string{"min_severity", "host", "cve", "limit"} {
		if _, ok := findings[p]; !ok {
			t.Errorf("hejnal_findings has no %q property", p)
		}
	}

	// hejnal_run needs permission, an engine and a scope.
	e := newEngine(t, dir, kevSample)
	sc := siteScope(t, "http://127.0.0.1:1")
	l := &logs{}
	for _, cfg := range []Config{
		{Store: state.Store{Dir: dir}, AllowRuns: true, Scope: sc, Logf: l.logf},
		{Engine: e, AllowRuns: true, Logf: l.logf},
		{Engine: e, Scope: sc},
	} {
		s := NewServer(cfg)
		if got, _ := names(s); slices.Contains(got, "hejnal_run") {
			t.Errorf("hejnal_run offered with %+v", cfg)
		}
		resps := exchange(t, s, toolCall(2, "hejnal_run", nil))
		if resps[0].Error == nil || resps[0].Error.Code != codeInvalidParams || !strings.Contains(resps[0].Error.Message, "does not allow runs") {
			t.Errorf("calling hejnal_run anyway: %+v", resps[0])
		}
	}
	if !strings.Contains(l.String(), "hejnal_run is not offered") {
		t.Errorf("the missing engine or scope was not logged:\n%s", l.String())
	}
	got, tools = names(NewServer(Config{Engine: e, Scope: sc, AllowRuns: true}))
	if !slices.Equal(got, append(readOnly, "hejnal_run")) {
		t.Fatalf("tools with runs allowed = %v", got)
	}
	a := tools[5]["annotations"].(map[string]any)
	if a["readOnlyHint"] != false || a["openWorldHint"] != true {
		t.Errorf("hejnal_run annotations = %v", a)
	}
}

func TestProtocolErrors(t *testing.T) {
	s := NewServer(Config{Store: writeState(t, t.TempDir())})
	cases := []struct {
		line string
		id   string
		code int
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, `1`, codeMethodNotFound},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hejnal_nope"}}`, `2`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{}}}`, `3`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":[1]}`, `4`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":5,"method":"tools/call"}`, `5`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":7}}`, `6`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":7,"method":"initialize","params":[]}`, `7`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":8,"method":"tools/list","params":{"cursor":"page-2"}}`, `8`, codeInvalidParams},
		{`{"jsonrpc":"2.0","id":9,"method":"ping"`, `null`, codeParseError},
		{`not json at all`, `null`, codeParseError},
		{`{"id":10,"method":"ping"}`, `10`, codeInvalidRequest},
		{`{"jsonrpc":"1.0","id":11,"method":"ping"}`, `11`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":{"n":12},"method":"ping"}`, `null`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":null,"method":"ping"}`, `null`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":true,"method":"ping"}`, `null`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":13,"method":7}`, `13`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":14}`, `14`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":15,"method":""}`, `15`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","id":16,"method":"ping","params":"x"}`, `16`, codeInvalidRequest},
		{`{"jsonrpc":"2.0","method":7}`, `null`, codeInvalidRequest},
		{`42`, `null`, codeInvalidRequest},
		{`[]`, `null`, codeInvalidRequest},
	}
	lines := make([]string, len(cases))
	for i, c := range cases {
		lines[i] = c.line
	}
	resps := exchange(t, s, lines...)
	if len(resps) != len(cases) {
		t.Fatalf("got %d responses for %d messages", len(resps), len(cases))
	}
	for i, c := range cases {
		r := resps[i]
		if r.Error == nil || r.Error.Code != c.code || string(r.ID) != c.id || r.Error.Message == "" {
			t.Errorf("%s: got id %s error %+v, want id %s code %d", c.line, r.ID, r.Error, c.id, c.code)
		}
	}
	if msg := resps[1].Error.Message; !strings.Contains(msg, `unknown tool "hejnal_nope"`) {
		t.Errorf("unknown tool message: %q", msg)
	}
}

func TestBatch(t *testing.T) {
	s := NewServer(Config{Store: state.Store{Dir: t.TempDir()}})
	in := strings.Join([]string{
		`[` + request(1, "ping", nil) + `,` + notify("notifications/initialized", nil) + `,` + request(2, "nope", nil) + `]`,
		`[` + notify("notifications/initialized", nil) + `]`,
		request(3, "ping", nil),
	}, "\n")
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := outputLines(out.Bytes())
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), out.Bytes())
	}
	var batch []json.RawMessage
	if err := json.Unmarshal(lines[0], &batch); err != nil || len(batch) != 2 {
		t.Fatalf("batch response = %s", lines[0])
	}
	if r := parseResponse(t, batch[0]); string(r.ID) != "1" || string(r.Result) != "{}" {
		t.Errorf("first batch response = %s", batch[0])
	}
	if r := parseResponse(t, batch[1]); string(r.ID) != "2" || r.Error == nil || r.Error.Code != codeMethodNotFound {
		t.Errorf("second batch response = %s", batch[1])
	}
	if r := parseResponse(t, lines[1]); string(r.ID) != "3" {
		t.Errorf("response after the batches = %s", lines[1])
	}
}

func TestLongLines(t *testing.T) {
	s := NewServer(Config{Store: state.Store{Dir: t.TempDir()}})
	padded := func(n int) string {
		head, tail := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"`, `"}}`
		return head + strings.Repeat("x", n-len(head)-len(tail)) + tail
	}
	atLimit := strings.Replace(padded(maxLine), `"id":1`, `"id":2`, 1)
	resps := exchange(t, s, padded(maxLine+1), atLimit, "\r", request(3, "ping", nil)+"\r")
	if len(resps) != 3 {
		t.Fatalf("got %d responses, want 3", len(resps))
	}
	if r := resps[0]; r.Error == nil || r.Error.Code != codeInvalidRequest || string(r.ID) != "null" || !strings.Contains(r.Error.Message, "4 MiB") {
		t.Errorf("too long: %+v", r)
	}
	if r := resps[1]; r.Error != nil || string(r.ID) != "2" {
		t.Errorf("at the limit: %+v", r.Error)
	}
	if r := resps[2]; r.Error != nil || string(r.ID) != "3" {
		t.Errorf("after a long line, with CRLF: %+v", r.Error)
	}
}

func TestCancelStopsARun(t *testing.T) {
	site := newSite(t, true)
	dir := t.TempDir()
	l := &logs{}
	s := NewServer(Config{Engine: newEngine(t, dir, kevSample), Scope: siteScope(t, site.URL), AllowRuns: true, Logf: l.logf})

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- s.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	responses := make(chan rpcResponse, 8)
	go func() {
		defer close(responses)
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			var r rpcResponse
			json.Unmarshal(sc.Bytes(), &r)
			responses <- r
		}
	}()
	send := func(line string) {
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatal(err)
		}
	}

	send(toolCall(7, "hejnal_run", nil))
	site.waitHit(t) // the run is in progress
	send(notify("notifications/cancelled", map[string]any{"requestId": 7, "reason": "the user stopped it"}))
	send(request(8, "ping", nil))
	select {
	case r := <-responses:
		if string(r.ID) != "8" {
			t.Errorf("first response is for request %s, want 8: the cancelled run was answered", r.ID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no response after cancelling the run")
	}
	// A request cancelled before it starts is not run either.
	send(notify("notifications/cancelled", map[string]any{"requestId": "later"}))
	send(toolCall("later", "hejnal_summary", nil))
	send(request(9, "ping", nil))
	if r := <-responses; string(r.ID) != "9" {
		t.Errorf("response for %s, want 9", r.ID)
	}
	inW.Close()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
	for r := range responses {
		t.Errorf("unexpected response %s", r.ID)
	}
	if _, err := (state.Store{Dir: dir}).LoadInventory(); !errors.Is(err, state.ErrNoInventory) {
		t.Errorf("the cancelled run saved an inventory: %v", err)
	}
	if !strings.Contains(l.String(), "the client cancelled request 7") {
		t.Errorf("cancellation not logged:\n%s", l.String())
	}
}

func TestServeStopsWhenContextEnds(t *testing.T) {
	s := NewServer(Config{Store: state.Store{Dir: t.TempDir()}})
	inR, inW := io.Pipe()
	defer inW.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, inR, io.Discard) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept waiting for input after the context ended")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestServeReportsIOErrors(t *testing.T) {
	s := NewServer(Config{Store: state.Store{Dir: t.TempDir()}})
	err := s.Serve(context.Background(), strings.NewReader(request(1, "ping", nil)+"\n"), brokenWriter{})
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Errorf("write error: %v", err)
	}
	err = s.Serve(context.Background(), iotest.ErrReader(errors.New("disk on fire")), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("read error: %v", err)
	}
	// Input that ends without a newline still counts.
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(request(1, "ping", nil)), &out); err != nil || !strings.Contains(out.String(), `"id":1`) {
		t.Errorf("last line without newline: %v %q", err, out.String())
	}
}

func TestMisconfiguredServerExplains(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir)
	e := newEngine(t, dir, kevSample)
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{}, "no state directory configured"},
		{Config{Store: state.Store{Dir: t.TempDir()}, Engine: e}, "is not the engine's"},
	}
	for _, c := range cases {
		l := &logs{}
		c.cfg.Logf = l.logf
		s := NewServer(c.cfg)
		for _, name := range []string{"hejnal_summary", "hejnal_inventory"} {
			r := callOne(t, s, name, nil)
			if !r.IsError || !strings.Contains(r.text(), c.want) {
				t.Errorf("%s: %+v", name, r)
			}
		}
		if !strings.Contains(l.String(), c.want) {
			t.Errorf("not logged: %s", l.String())
		}
	}
	// The engine's state directory is used when Store is empty.
	if r := callOne(t, NewServer(Config{Engine: e}), "hejnal_summary", nil); r.IsError {
		t.Errorf("engine's state directory: %s", r.text())
	}
	// An unknown language falls back to English.
	l := &logs{}
	s := NewServer(Config{Store: state.Store{Dir: dir}, Lang: "de", Logf: l.logf})
	if r := callOne(t, s, "hejnal_fix_list", nil); !strings.Contains(r.text(), "# Hejnal fix list") {
		t.Errorf("fix list with an unknown default language: %s", r.text())
	}
	if !strings.Contains(l.String(), `unknown report language "de"`) {
		t.Errorf("language not logged: %s", l.String())
	}
}
