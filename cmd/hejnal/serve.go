package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Legatia/hejnal/api"
	"github.com/Legatia/hejnal/engine"
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
	// Serve logs the address, and warns when it is reachable from other
	// machines over plain HTTP.
	return api.Serve(ctx, *addr, h, a.logf)
}

func (a *app) cmdMCP(ctx context.Context, args []string) error {
	o := &options{}
	fs := a.flags("mcp", "[flags]",
		"Run a Model Context Protocol server on standard input and output, so an AI\nassistant can read the fix list, findings and inventory. Add it to the\nassistant's MCP settings as the command `hejnal mcp -state /path/to/.hejnal`.\n\n"+
			"With -code, a coding assistant can also check a source directory, fix an\nitem there and ask whether Hejnal still finds it. With -allow-runs it can do\nthe same for one system in the scope.")
	allowRuns := fs.Bool("allow-runs", false, "let the assistant start a scan of the scope, and check one system in it as hejnal live does, fixed paths included")
	var code listFlag
	fs.Var(&code, "code", "let the assistant check the source code in this `directory`: dependencies, secrets and infrastructure code (repeatable)")
	project := fs.String("project", "", "with -code, the `name` of the project, as hejnal code scan -project has it (default: the directory's name)")
	var exclude listFlag
	fs.Var(&exclude, "exclude", "with -code, "+excludeHelp)
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
	req, err := mcpCode(code, *project, exclude, o.offline)
	if err != nil {
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
		Code:      req,
		Lang:      o.lang,
		Now:       a.now,
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

// mcpCode reads the flags that let an assistant check source code: the
// directories, as absolute paths, since the assistant starts the server
// from a directory of its own choosing.
func mcpCode(dirs []string, project string, exclude []string, offline bool) (engine.CodeRequest, error) {
	var req engine.CodeRequest
	if len(dirs) == 0 {
		if project != "" || len(exclude) > 0 {
			return req, errors.New("-project and -exclude describe the directory of -code: name it with -code")
		}
		return req, nil
	}
	if offline {
		return req, errors.New("-code checks dependencies with OSV's API: run without -offline")
	}
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			return req, err
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return req, fmt.Errorf("-code %s is not a directory", d)
		}
		req.Dirs = append(req.Dirs, abs)
	}
	req.Project = project
	if req.Project == "" {
		req.Project = filepath.Base(req.Dirs[0])
	}
	var err error
	req.Exclude, err = excludeDirs(exclude)
	return req, err
}

// scopeLoader reads the scope file each time it is needed, so edits apply
// to the next run without a restart.
func (a *app) scopeLoader(path string) func() (*scope.Scope, error) {
	return func() (*scope.Scope, error) { return a.loadScope(path) }
}
