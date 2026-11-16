package engine

import (
	"context"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
)

// Look reports what answers on the named systems right now, and nothing
// else in the scope: no other host, no certificate transparency logs, no
// mail records. With checks set it also asks for the fixed paths and
// product versions of Config.Checks. The scope's rules hold as in any run.
//
// Nothing is saved: the inventory and the record of systems stay as the
// last full run left them, so looking at one system does not make the
// others appear gone.
func (e *Engine) Look(ctx context.Context, s *scope.Scope, targets []discover.Target, checks bool) (*inventory.Inventory, error) {
	opts := e.discoverOptions(s)
	opts.Only = targets
	opts.Checks = checks
	// Discovery logs its progress through a scope; for a system or two
	// that says nothing, and a caller may look many times while waiting.
	opts.Logf = func(string, ...any) {}
	if len(targets) == 0 {
		// Without targets, discovery would run over the whole scope.
		return &inventory.Inventory{Organization: s.Organization, GeneratedAt: e.cfg.Now().UTC()}, nil
	}
	return discover.Run(ctx, opts)
}

// Assess matches what Look found against the lists of exploited flaws and
// the end-of-support dates, and marks the items people accepted. Leaked
// secrets and code scans kept in the state directory are left out, since
// they are not about these systems. Nothing is saved but the feed cache,
// so the fix list and what people were told stay as they are.
func (e *Engine) Assess(ctx context.Context, inv *inventory.Inventory) (*state.Snapshot, error) {
	cat, err := e.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	return e.snapshot(ctx, inv, cat, false)
}
