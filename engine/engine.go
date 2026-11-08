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
	"runtime"
	"slices"
	"time"

	"github.com/Legatia/hejnal/discover"
	"github.com/Legatia/hejnal/epss"
	"github.com/Legatia/hejnal/euvd"
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
	// euvdRecordMaxAge is how long a downloaded EUVD record is used before
	// refreshing, and euvdRecordBudget how many records one run downloads.
	euvdRecordMaxAge = 7 * 24 * time.Hour
	euvdRecordBudget = 50
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
	// EUVDURL and EUVDRecordURL are ENISA's EUVD endpoints for its list of
	// exploited vulnerabilities and for single records.
	EUVDURL       string
	EUVDRecordURL string
	// EUVDFile reads ENISA's list from a file instead of downloading it.
	// With KEVFile or EUVDFile set, Hejnal downloads nothing from ENISA and
	// uses the saved copy of the list, if there is one.
	EUVDFile string

	// Offline never downloads feeds and uses cached copies only.
	Offline bool
	NoEPSS  bool
	NoCT    bool
	// NoNVD skips comparing versions with NVD's affected ranges.
	NoNVD bool
	// NoEUVD leaves out ENISA's list of exploited vulnerabilities.
	NoEUVD bool
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
	if cfg.EUVDURL == "" {
		cfg.EUVDURL = euvd.DefaultURL
	}
	if cfg.EUVDRecordURL == "" {
		cfg.EUVDRecordURL = euvd.DefaultRecordURL
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
	warnLoosePermissions(cfg.Logf, cfg.StateDir, cfg.CacheDir)
	return &Engine{cfg: cfg, store: state.Store{Dir: cfg.StateDir}, rules: rules}, nil
}

// warnLoosePermissions warns about state or cache directories other users
// can write to: Hejnal trusts what it finds there, such as cached NVD
// records that can rule flaws out.
func warnLoosePermissions(logf func(string, ...any), dirs ...string) {
	if runtime.GOOS == "windows" {
		return
	}
	for _, dir := range dirs {
		if st, err := os.Stat(dir); err == nil && st.IsDir() && st.Mode().Perm()&0o022 != 0 {
			logf("warning: other users can write to %s, and Hejnal trusts what it finds there; run `chmod go-w %s`", dir, dir)
		}
	}
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

// RefreshCatalog downloads the KEV catalog and ENISA's list into the cache,
// and returns the catalog with ENISA's list merged in.
func (e *Engine) RefreshCatalog(ctx context.Context) (*kev.Catalog, error) {
	cat, err := kev.Fetch(ctx, e.cfg.HTTPClient, e.cfg.KEVURL, version.UserAgent(), e.kevPath())
	if err != nil {
		return nil, err
	}
	if !e.cfg.NoEUVD {
		if _, err := euvd.Fetch(ctx, e.cfg.HTTPClient, e.cfg.EUVDURL, version.UserAgent(), e.euvdPath()); err != nil {
			e.cfg.Logf("could not download ENISA's list of exploited vulnerabilities (%v)", err)
		}
	}
	e.addEUVD(ctx, cat)
	return cat, nil
}

// Catalog returns the KEV catalog with ENISA's list merged in. CISA's catalog
// comes from KEVFile if set, from the cache while it is fresh, and otherwise
// is downloaded; a failed download falls back to the cached copy. ENISA's
// list is optional: without it, the catalog is CISA's alone.
func (e *Engine) Catalog(ctx context.Context) (*kev.Catalog, error) {
	cat, err := e.cisaCatalog(ctx)
	if err != nil {
		return nil, err
	}
	e.addEUVD(ctx, cat)
	return cat, nil
}

func (e *Engine) cisaCatalog(ctx context.Context) (*kev.Catalog, error) {
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
	cat, err := kev.Fetch(ctx, e.cfg.HTTPClient, e.cfg.KEVURL, version.UserAgent(), path)
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

func (e *Engine) euvdPath() string { return filepath.Join(e.cfg.CacheDir, "euvd-kev.json") }

// euvdOnline reports whether Hejnal may download from ENISA: not offline,
// and not reading the feeds from files.
func (e *Engine) euvdOnline() bool {
	return !e.cfg.Offline && e.cfg.KEVFile == "" && e.cfg.EUVDFile == ""
}

// addEUVD merges ENISA's list of exploited vulnerabilities into cat.
func (e *Engine) addEUVD(ctx context.Context, cat *kev.Catalog) {
	if e.cfg.NoEUVD || cat.EUVDDate != "" {
		return
	}
	entries, date, err := e.euvdList(ctx)
	if err != nil {
		// Reading feeds from files with no saved copy of ENISA's list is
		// a choice, not a problem.
		if !(errors.Is(err, os.ErrNotExist) && !e.euvdOnline()) {
			e.cfg.Logf("ENISA's list of exploited vulnerabilities is not available (%v); using CISA's catalog alone", err)
		}
		return
	}
	records := e.euvdRecords(ctx, euvd.ENISAOnly(cat, entries))
	euvd.Merge(cat, entries, records)
	cat.EUVDDate = date
}

// euvdList returns ENISA's list and its date. ENISA publishes it every day
// at 07:00 UTC, so a copy saved since then is current.
func (e *Engine) euvdList(ctx context.Context) ([]euvd.Entry, string, error) {
	path := e.euvdPath()
	if e.cfg.EUVDFile != "" {
		path = e.cfg.EUVDFile
	}
	load := func() ([]euvd.Entry, string, error) {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, "", err
		}
		entries, err := euvd.Load(path)
		if err != nil {
			return nil, "", err
		}
		return entries, euvd.Published(fi.ModTime()).Format("2006-01-02"), nil
	}
	if !e.euvdOnline() {
		return load()
	}
	if fi, err := os.Stat(path); err == nil && !fi.ModTime().Before(euvd.Published(time.Now())) {
		if entries, date, err := load(); err == nil {
			return entries, date, nil
		}
	}
	entries, err := euvd.Fetch(ctx, e.cfg.HTTPClient, e.cfg.EUVDURL, version.UserAgent(), path)
	if err != nil {
		if cached, date, cerr := load(); cerr == nil {
			e.cfg.Logf("could not refresh ENISA's list of exploited vulnerabilities (%v); using the copy of %s", err, date)
			return cached, date, nil
		}
		return nil, "", err
	}
	only := 0
	for _, x := range entries {
		if !slices.Contains(x.Sources, euvd.SourceCISA) {
			only++
		}
	}
	e.cfg.Logf("downloaded ENISA's list of exploited vulnerabilities (%d flaws, %d not in CISA's list)", len(entries), only)
	return entries, euvd.Published(time.Now()).Format("2006-01-02"), nil
}

// euvdRecords returns the EUVD records of flaws only ENISA lists, for their
// description and advisories, refreshing stale ones while online.
func (e *Engine) euvdRecords(ctx context.Context, entries []euvd.Entry) map[string]*euvd.Record {
	if len(entries) == 0 {
		return nil
	}
	cache := euvd.Cache{Dir: filepath.Join(e.cfg.CacheDir, "euvd")}
	out := map[string]*euvd.Record{}
	var fetch []string
	for _, x := range entries {
		rec, fetched, ok := cache.Get(x.EUVDID)
		if ok {
			out[x.EUVDID] = rec
		}
		if !ok || time.Since(fetched) > euvdRecordMaxAge {
			fetch = append(fetch, x.EUVDID)
		}
	}
	if !e.euvdOnline() {
		return out
	}
	for i, id := range fetch {
		if i == euvdRecordBudget {
			break
		}
		rec, err := euvd.FetchRecord(ctx, e.cfg.HTTPClient, e.cfg.EUVDRecordURL, version.UserAgent(), id)
		if errors.Is(err, euvd.ErrNotFound) {
			continue
		}
		if err != nil {
			e.cfg.Logf("EUVD lookup failed (%v); continuing without details for the rest", err)
			break
		}
		out[id] = rec
		if err := cache.Put(rec, time.Now()); err != nil {
			e.cfg.Logf("could not cache EUVD data: %v", err)
		}
	}
	return out
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
		EUVDDate:     cat.EUVDDate,
		KEVFlaws:     len(cat.Vulnerabilities),
		Findings:     fs,
	}
	snap.Assets, snap.Services, snap.Technologies = inv.Counts()
	for _, f := range fs {
		if s, ok := scores[f.CVE]; ok && s.Date > snap.EPSSDate {
			snap.EPSSDate = s.Date
		}
	}
	// The saved findings say which ones people accepted, and until when.
	if err := e.store.MarkAccepted(snap, now); err != nil {
		return nil, err
	}
	if err := e.store.SaveFindings(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// Changes compares a snapshot with what people were last told about.
type Changes struct {
	// Added are the open findings that were not open at the last report:
	// new ones, and ones whose acceptance expired or was removed.
	Added []match.Finding
	// Resolved are the findings gone since the last report, or now ruled
	// out by the version check.
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
	// Flaws the version check rules out are not news, and neither are
	// findings people accepted. Comparing only the open findings also
	// announces a flaw that becomes active again, say when a server stops
	// showing its version, and a finding whose acceptance expired. Only
	// findings that are gone count as resolved, so accepting one does not
	// resolve it, while a flaw the version check now rules out is resolved.
	if prev == nil {
		return Changes{Added: match.Open(snap.Findings), First: true}, nil
	}
	added, _ := state.Diff(match.Open(prev.Findings), match.Open(snap.Findings))
	_, resolved := state.Diff(match.Active(prev.Findings), match.Active(snap.Findings))
	return Changes{Added: added, Resolved: resolved}, nil
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
		EUVDDate:     snap.EUVDDate,
		EPSSDate:     snap.EPSSDate,
		KEVFlaws:     snap.KEVFlaws,
		Assets:       snap.Assets,
		Services:     snap.Services,
		Technologies: snap.Technologies,
	}
}
