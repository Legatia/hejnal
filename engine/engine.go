// Package engine runs Hejnal end to end: discovery inside the scope, matching
// against the catalog of exploited flaws, and the state that tells what is
// new. The command line, the REST API, the MCP server and the hosted service
// all build on it.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/epss"
	"github.com/Legatia/hejnal/fingerprint"
	"github.com/Legatia/hejnal/inventory"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/nvd"
	"github.com/Legatia/hejnal/report"
	"github.com/Legatia/hejnal/scope"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

const (
	// KEVMaxAge is how long a downloaded catalog is used before refreshing.
	KEVMaxAge = 6 * time.Hour
	// epssMaxAgeDays is how old, in days, a cached EPSS score may be.
	epssMaxAgeDays = 2
)

// Config configures an engine. Only StateDir is required.
type Config struct {
	// StateDir keeps results between runs.
	StateDir string
	// CacheDir keeps downloaded feeds. Defaults to StateDir/cache. Several
	// engines may share one cache directory.
	CacheDir string

	// KEVFile reads the catalog from a file instead of downloading it.
	KEVFile string
	KEVURL  string
	EPSSURL string
	CTURL   string
	NVDURL  string
	// NVDKey raises NVD's rate limit, so version checks finish sooner.
	NVDKey string

	// Offline never downloads feeds and uses cached copies only.
	Offline bool
	NoEPSS  bool
	NoCT    bool
	// NoNVD skips comparing versions with NVD's affected ranges.
	NoNVD bool
	// Checks turns on the opt-in checks for exposed files and versions.
	Checks bool

	Concurrency int
	Timeout     time.Duration

	// HTTPClient fetches feeds. Discovery uses its own scope-checked client.
	HTTPClient *http.Client
	Resolver   discover.Resolver
	Now        func() time.Time
	Logf       func(format string, args ...any)

	nvdPause time.Duration // shortens NVD pacing in tests
}

// Engine runs discovery and matching for one organisation's state directory.
type Engine struct {
	cfg   Config
	store state.Store
	rules *fingerprint.Engine
}

// New prepares an engine.
func New(cfg Config) (*Engine, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("engine: StateDir is required")
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = filepath.Join(cfg.StateDir, "cache")
	}
	if cfg.KEVURL == "" {
		cfg.KEVURL = kev.DefaultURL
	}
	if cfg.EPSSURL == "" {
		cfg.EPSSURL = epss.DefaultAPI
	}
	if cfg.CTURL == "" {
		cfg.CTURL = discover.CrtShURL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 2 * time.Minute}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	rules, err := fingerprint.Default()
	if err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg, store: state.Store{Dir: cfg.StateDir}, rules: rules}, nil
}

// Store returns the engine's state directory.
func (e *Engine) Store() state.Store { return e.store }

// Rules returns the fingerprint rules.
func (e *Engine) Rules() *fingerprint.Engine { return e.rules }

// Discover finds hosts and services in the scope and saves the inventory.
func (e *Engine) Discover(ctx context.Context, s *scope.Scope) (*inventory.Inventory, error) {
	opts := discover.Options{
		Scope:       s,
		Engine:      e.rules,
		Resolver:    e.cfg.Resolver,
		Concurrency: e.cfg.Concurrency,
		Timeout:     e.cfg.Timeout,
		UserAgent:   version.UserAgent(),
		Checks:      e.cfg.Checks,
		Now:         e.cfg.Now,
		Logf:        e.cfg.Logf,
	}
	if !e.cfg.NoCT && len(s.Domains) > 0 {
		opts.CT = &discover.CrtSh{Client: e.cfg.HTTPClient, BaseURL: e.cfg.CTURL, UserAgent: version.UserAgent()}
	}
	inv, err := discover.Run(ctx, opts)
	if err != nil {
		return nil, err
	}
	assets, services, techs := inv.Counts()
	e.cfg.Logf("found %d hosts, %d services and %d products", assets, services, techs)
	if err := e.store.SaveInventory(inv); err != nil {
		return nil, err
	}
	return inv, nil
}

func (e *Engine) kevPath() string { return filepath.Join(e.cfg.CacheDir, "kev.json") }

// RefreshCatalog downloads the KEV catalog into the cache.
func (e *Engine) RefreshCatalog(ctx context.Context) (*kev.Catalog, error) {
	return kev.Fetch(ctx, e.cfg.HTTPClient, e.cfg.KEVURL, version.UserAgent(), e.kevPath())
}

// Catalog returns the KEV catalog: from KEVFile if set, from the cache while
// it is fresh, and otherwise downloaded. A failed download falls back to the
// cached copy.
func (e *Engine) Catalog(ctx context.Context) (*kev.Catalog, error) {
	if e.cfg.KEVFile != "" {
		return kev.Load(e.cfg.KEVFile)
	}
	path := e.kevPath()
	if e.cfg.Offline {
		cat, err := kev.Load(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no cached KEV catalog at %s: run `hejnal feeds` while online, or pass -kev-file", path)
		}
		return cat, err
	}
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < KEVMaxAge {
		if cat, err := kev.Load(path); err == nil {
			return cat, nil
		}
	}
	cat, err := e.RefreshCatalog(ctx)
	if err != nil {
		if cached, cerr := kev.Load(path); cerr == nil {
			e.cfg.Logf("could not refresh the KEV catalog (%v); using cached catalog %s", err, cached.CatalogVersion)
			return cached, nil
		}
		return nil, err
	}
	e.cfg.Logf("downloaded CISA KEV catalog %s (%d flaws)", cat.CatalogVersion, len(cat.Vulnerabilities))
	return cat, nil
}

// epssScores returns EPSS scores for the CVEs, refreshing stale ones.
func (e *Engine) epssScores(ctx context.Context, cves []string) map[string]epss.Score {
	if e.cfg.NoEPSS || len(cves) == 0 {
		return nil
	}
	path := filepath.Join(e.cfg.CacheDir, "epss.json")
	cache, err := epss.LoadCache(path)
	if err != nil {
		e.cfg.Logf("ignoring unreadable EPSS cache: %v", err)
		cache = map[string]epss.Score{}
	}
	if e.cfg.Offline {
		return cache
	}
	// EPSS publishes new scores every day, dated by the day they describe.
	stale := e.cfg.Now().UTC().AddDate(0, 0, -epssMaxAgeDays).Format("2006-01-02")
	var want []string
	for _, c := range cves {
		if s, ok := cache[c]; !ok || s.Date < stale {
			want = append(want, c)
		}
	}
	if len(want) == 0 {
		return cache
	}
	scores, err := epss.Fetch(ctx, e.cfg.HTTPClient, e.cfg.EPSSURL, version.UserAgent(), want)
	if err != nil {
		e.cfg.Logf("could not fetch EPSS scores (%v); continuing without fresh scores", err)
		return cache
	}
	for k, v := range scores {
		cache[k] = v
	}
	if err := epss.SaveCache(path, cache); err != nil {
		e.cfg.Logf("could not save EPSS cache: %v", err)
	}
	return cache
}

// nvdBudget is how many NVD records one run fetches, without and with an
// API key. The cache keeps them, so later runs complete the picture.
const (
	nvdBudget    = 20
	nvdBudgetKey = 200
)

// nvdRecords returns NVD affected-version data for findings whose product
// version is known and has an NVD name.
func (e *Engine) nvdRecords(ctx context.Context, candidates []match.Finding) map[string]*nvd.Record {
	if e.cfg.NoNVD {
		return nil
	}
	var want []string
	for _, f := range candidates {
		if f.Kind == match.KindKEV && f.Version != "" && len(e.rules.CPEs(f.TechID)) > 0 {
			want = append(want, f.CVE)
		}
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if len(want) == 0 {
		return nil
	}
	cache := nvd.Cache{Dir: filepath.Join(e.cfg.CacheDir, "nvd")}
	out := map[string]*nvd.Record{}
	var fetch []string
	for _, c := range want {
		rec, ok := cache.Get(c)
		if ok {
			out[c] = rec
		}
		if !ok || nvd.Stale(rec, time.Now()) {
			fetch = append(fetch, c)
		}
	}
	if e.cfg.Offline || len(fetch) == 0 {
		return out
	}
	budget := nvdBudget
	if e.cfg.NVDKey != "" {
		budget = nvdBudgetKey
	}
	client := &nvd.Client{HTTP: e.cfg.HTTPClient, BaseURL: e.cfg.NVDURL, APIKey: e.cfg.NVDKey, UserAgent: version.UserAgent(), Pause: e.cfg.nvdPause}
	for i, c := range fetch {
		if i == budget {
			e.cfg.Logf("NVD: %d version checks left for the next runs; an NVD API key (HEJNAL_NVD_API_KEY) makes them faster", len(fetch)-i)
			break
		}
		rec, err := client.Fetch(ctx, c)
		if err != nil {
			// Stop at the first failure: NVD is down, rate limiting or not
			// reachable, and retrying every CVE would only add waiting.
			e.cfg.Logf("NVD lookup failed (%v); continuing without version checks for the rest", err)
			break
		}
		out[c] = rec
		if err := cache.Put(rec); err != nil {
			e.cfg.Logf("could not cache NVD data: %v", err)
		}
	}
	return out
}

// Match matches an inventory against the catalog and saves the findings.
func (e *Engine) Match(ctx context.Context, inv *inventory.Inventory) (*state.Snapshot, error) {
	cat, err := e.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	return e.MatchCatalog(ctx, inv, cat)
}

// MatchCatalog matches an inventory against a given catalog and saves the
// findings. The hosted service uses it to re-match every organisation as
// soon as the catalog changes, without scanning again.
func (e *Engine) MatchCatalog(ctx context.Context, inv *inventory.Inventory, cat *kev.Catalog) (*state.Snapshot, error) {
	now := e.cfg.Now()
	candidates := match.Run(inv, cat, e.rules, match.Options{Now: now})
	scores := e.epssScores(ctx, match.CVEs(candidates))
	records := e.nvdRecords(ctx, candidates)
	fs := match.Run(inv, cat, e.rules, match.Options{Now: now, EPSS: scores, NVD: records})
	leaked, err := e.leakFindings(now)
	if err != nil {
		return nil, err
	}
	if len(leaked) > 0 {
		fs = append(fs, leaked...)
		match.Sort(fs)
	}
	snap := &state.Snapshot{
		Organization: inv.Organization,
		GeneratedAt:  now.UTC(),
		KEVVersion:   cat.CatalogVersion,
		Findings:     fs,
	}
	snap.Assets, snap.Services, snap.Technologies = inv.Counts()
	for _, f := range fs {
		if s, ok := scores[f.CVE]; ok && s.Date > snap.EPSSDate {
			snap.EPSSDate = s.Date
		}
	}
	if err := e.store.SaveFindings(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// Changes compares a snapshot with what people were last told about.
type Changes struct {
	Added    []match.Finding
	Resolved []match.Finding
	// First is true before anything was reported.
	First bool
}

// leakFindings returns findings from the saved secret scan and breach check,
// which `hejnal leaks` writes. They stay until the next scan or check
// replaces them.
func (e *Engine) leakFindings(now time.Time) ([]match.Finding, error) {
	var out []match.Finding
	scan, err := e.store.LoadLeakScan()
	if err != nil {
		return nil, err
	}
	if scan != nil {
		out = append(out, match.Secrets(scan.Leaks)...)
	}
	check, err := e.store.LoadBreachCheck()
	if err != nil {
		return nil, err
	}
	if check != nil {
		out = append(out, match.Breaches(check.Domains, now)...)
	}
	return out, nil
}

// Changes returns what is new and what was fixed since the last report.
func (e *Engine) Changes(snap *state.Snapshot) (Changes, error) {
	prev, err := e.store.LoadReported()
	if err != nil {
		return Changes{}, err
	}
	// Flaws the version check rules out are not news.
	if prev == nil {
		return Changes{Added: match.Active(snap.Findings), First: true}, nil
	}
	added, resolved := state.Diff(prev.Findings, snap.Findings)
	return Changes{Added: match.Active(added), Resolved: resolved}, nil
}

// MarkReported records that people were told about snap. Call it only after
// every notification succeeded, so failed ones are repeated next time.
func (e *Engine) MarkReported(snap *state.Snapshot) error {
	return e.store.SaveReported(snap)
}

// Result is one complete run.
type Result struct {
	Inventory *inventory.Inventory
	Snapshot  *state.Snapshot
	Changes   Changes
}

// Run discovers, matches and compares with the last report.
func (e *Engine) Run(ctx context.Context, s *scope.Scope) (*Result, error) {
	inv, err := e.Discover(ctx, s)
	if err != nil {
		return nil, err
	}
	snap, err := e.Match(ctx, inv)
	if err != nil {
		return nil, err
	}
	ch, err := e.Changes(snap)
	if err != nil {
		return nil, err
	}
	return &Result{Inventory: inv, Snapshot: snap, Changes: ch}, nil
}

// Meta describes a snapshot for reports.
func Meta(snap *state.Snapshot, lang string) report.Meta {
	return report.Meta{
		Organization: snap.Organization,
		GeneratedAt:  snap.GeneratedAt,
		Lang:         lang,
		KEVVersion:   snap.KEVVersion,
		EPSSDate:     snap.EPSSDate,
		Assets:       snap.Assets,
		Services:     snap.Services,
		Technologies: snap.Technologies,
	}
}
