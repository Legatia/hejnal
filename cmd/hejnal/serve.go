package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/Legatia/hejnal/api"
	"github.com/Legatia/hejnal/mcp"
	"github.com/Legatia/hejnal/scope"
)

func (a *app) cmdServe(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("serve", "[-addr 127.0.0.1:8080] [flags]",
		"Serve the saved results over a REST API. Clients authenticate with the\ntoken in HEJNAL_API_TOKEN (at least 32 characters, for example from\n`openssl rand -hex 32`). The API has no TLS of its own: keep it on a local\naddress, or put it behind a reverse proxy that terminates TLS.")
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on")
	allowRuns := fs.Bool("allow-runs", false, "allow clients to start a scan of the scope with POST /v1/runs")
	o.scanFlags(fs)
	o.stateFlags(fs)
	o.feedFlags(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	token := os.Getenv("HEJNAL_API_TOKEN")
	if len(token) < api.MinTokenLength {
		return fmt.Errorf("set HEJNAL_API_TOKEN to a random value of at least %d characters, for example from `openssl rand -hex 32`", api.MinTokenLength)
	}
	e, err := a.engine(o)
	if err != nil {
		return err
	}
	cfg := api.Config{
		Store:     e.Store(),
		Token:     token,
		Engine:    e,
		AllowRuns: *allowRuns,
		Now:       a.now,
		Logf:      a.logf,
	}
	if *allowRuns {
		s, err := a.loadScope(o.scope)
		if err != nil {
			return err
		}
		a.printBanner(s)
		cfg.Scope = a.scopeLoader(o.scope)
	}
	h, err := api.NewHandler(cfg)
	if err != nil {
		return err
	}
	if !loopback(*addr) {
		a.logf("listening on %s, which is not a loopback address; use TLS in front of the API so the token is not sent in clear text", *addr)
	}
	a.logf("serving the API on http://%s/v1/", *addr)
	return api.Serve(ctx, *addr, h, a.logf)
}

func (a *app) cmdMCP(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("mcp", "[flags]",
		"Run a Model Context Protocol server on standard input and output, so an AI\nassistant can read the fix list, findings and inventory. Add it to the\nassistant's MCP settings as the command `hejnal mcp -state /path/to/.hejnal`.")
	allowRuns := fs.Bool("allow-runs", false, "let the assistant start a scan of the scope")
	o.scanFlags(fs)
	o.stateFlags(fs)
	o.feedFlags(fs)
	o.langFlag(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := o.check(); err != nil {
		return err
	}
	e, err := a.engine(o)
	if err != nil {
		return err
	}
	cfg := mcp.Config{
		Store:     e.Store(),
		Engine:    e,
		AllowRuns: *allowRuns,
		Lang:      o.lang,
		Logf:      a.logf,
	}
	if *allowRuns {
		if _, err := a.loadScope(o.scope); err != nil {
			return err
		}
		cfg.Scope = a.scopeLoader(o.scope)
	}
	return mcp.NewServer(cfg).Serve(ctx, a.stdin, a.stdout)
}

// scopeLoader reads the scope file each time it is needed, so edits apply
// to the next run without a restart.
func (a *app) scopeLoader(path string) func() (*scope.Scope, error) {
	return func() (*scope.Scope, error) { return a.loadScope(path) }
}

// loopback reports whether addr only listens on the local machine.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
