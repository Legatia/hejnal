package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/Legatia/hejnal/container"
	"github.com/Legatia/hejnal/deps"
	"github.com/Legatia/hejnal/iac"
	"github.com/Legatia/hejnal/kev"
	"github.com/Legatia/hejnal/leaks"
	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/osv"
	"github.com/Legatia/hejnal/state"
	"github.com/Legatia/hejnal/version"
)

// Parts of a code scan.
const (
	PartDeps    = "dependencies"
	PartSecrets = "secrets"
	PartIaC     = "infrastructure"
	PartImages  = "images"
)

// CodeRequest says what a code scan covers.
type CodeRequest struct {
	Project string
	// Dirs are source directories; Images are container images saved
	// with docker save or as OCI layouts.
	Dirs   []string
	Images []string
	// Skip names parts not to run: PartDeps, PartSecrets or PartIaC.
	Skip []string
	// History also scans the Git history for secrets.
	History bool
	// FingerprintKey keys secret fingerprints, as `hejnal leaks` does.
	FingerprintKey []byte
}

// ScanCode checks source directories and container images: dependencies
// against OSV, secrets with the leaks rules, and infrastructure code.
// Only package names and versions leave the machine, to OSV and, as CVE
// IDs, to FIRST's EPSS API.
func (e *Engine) ScanCode(ctx context.Context, req CodeRequest) (*state.CodeScan, error) {
	now := e.cfg.Now()
	scan := &state.CodeScan{ScannedAt: now.UTC(), Project: req.Project}
	skip := func(p string) bool { return slices.Contains(req.Skip, p) }
	label := func(root string) string {
		if len(req.Dirs) == 1 {
			return ""
		}
		return filepath.Base(root) + "/"
	}
	var pkgs []deps.Package
	var findings []match.Finding
	for _, dir := range req.Dirs {
		root, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		prefix := label(root)
		if !skip(PartDeps) {
			ps, problems, err := deps.ScanDir(ctx, root)
			if err != nil {
				return nil, err
			}
			for _, p := range problems {
				scan.Notes = append(scan.Notes, fmt.Sprintf("could not read %s%s: %s", prefix, p.File, p.Err))
			}
			for i := range ps {
				ps[i].File = prefix + ps[i].File
			}
			pkgs = append(pkgs, ps...)
		}
		if !skip(PartSecrets) {
			opts := leaks.Options{FingerprintKey: req.FingerprintKey}
			ls, err := leaks.ScanDir(ctx, root, opts)
			if err != nil {
				return nil, err
			}
			if req.History {
				hist, err := leaks.ScanGitHistory(ctx, root, opts)
				if err != nil {
					scan.Notes = append(scan.Notes, "Git history not scanned: "+err.Error())
				}
				ls = mergeLeaks(ls, hist)
			}
			for i := range ls {
				ls[i].File = prefix + ls[i].File
			}
			fs := match.Secrets(ls)
			for i := range fs {
				fs[i].Host = req.Project
			}
			findings = append(findings, fs...)
		}
		if !skip(PartIaC) {
			issues, err := iac.ScanDir(ctx, root)
			if err != nil {
				return nil, err
			}
			for i := range issues {
				issues[i].File = prefix + issues[i].File
			}
			findings = append(findings, match.Misconfigs(req.Project, issues)...)
		}
	}
	for _, src := range req.Images {
		img, err := container.Read(ctx, src)
		if err != nil {
			return nil, fmt.Errorf("image %s: %w", src, err)
		}
		name := img.Name
		if name == "" {
			name = filepath.Base(src)
		}
		scan.Images = append(scan.Images, name)
		for _, n := range img.Notes {
			scan.Notes = append(scan.Notes, name+": "+n)
		}
		for _, p := range img.Packages {
			p.File = name + ":" + p.File
			pkgs = append(pkgs, p)
		}
	}
	for _, p := range []string{PartDeps, PartSecrets, PartIaC} {
		if !skip(p) && len(req.Dirs) > 0 {
			scan.Parts = append(scan.Parts, p)
		}
	}
	if len(req.Images) > 0 {
		scan.Parts = append(scan.Parts, PartImages)
	}
	scan.Packages = len(pkgs)
	if len(pkgs) > 0 {
		dfs, err := e.dependencyFindings(ctx, req.Project, pkgs, now)
		if err != nil {
			return nil, err
		}
		findings = append(findings, dfs...)
	}
	match.Sort(findings)
	scan.Findings = findings
	return scan, nil
}

// OSVURL is where advisories come from unless the configuration says.
func (e *Engine) osvClient() *osv.Client {
	return &osv.Client{HTTP: e.cfg.HTTPClient, Base: e.cfg.OSVURL, UserAgent: version.UserAgent(), CacheDir: filepath.Join(e.cfg.CacheDir, "osv")}
}

func (e *Engine) dependencyFindings(ctx context.Context, project string, pkgs []deps.Package, now time.Time) ([]match.Finding, error) {
	if e.cfg.Offline {
		return nil, errors.New("checking dependencies needs OSV's API: run without -offline, or skip them with -no-deps")
	}
	// Ask about each package version once, however many files have it.
	type key struct{ eco, name, version string }
	index := map[key]int{}
	var qs []osv.Query
	for _, p := range pkgs {
		k := key{p.Ecosystem, p.Name, p.Version}
		if _, ok := index[k]; !ok {
			index[k] = len(qs)
			qs = append(qs, osv.Query{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version})
		}
	}
	ms, err := e.osvClient().Lookup(ctx, qs)
	if err != nil {
		return nil, err
	}
	byQuery := map[key][]*osv.Vuln{}
	for _, m := range ms {
		k := key{m.Query.Ecosystem, m.Query.Name, m.Query.Version}
		byQuery[k] = append(byQuery[k], m.Vuln)
	}
	var dms []match.DepMatch
	var cves []string
	for _, p := range pkgs {
		for _, v := range byQuery[key{p.Ecosystem, p.Name, p.Version}] {
			dms = append(dms, match.DepMatch{Package: p, Vuln: v})
			cves = append(cves, v.CVEs()...)
		}
	}
	cat, err := e.Catalog(ctx)
	if err != nil {
		e.cfg.Logf("no list of exploited flaws (%v); dependencies are rated by EPSS and their advisories only", err)
		cat = &kev.Catalog{}
	}
	slices.Sort(cves)
	return match.Dependencies(dms, match.DependencyOptions{Project: project, Catalog: cat, EPSS: e.epssScores(ctx, slices.Compact(cves)), Now: now}), nil
}

// codeFindings returns the saved code scans' findings, scored again
// against the current lists of exploited flaws.
func (e *Engine) codeFindings(ctx context.Context, cat *kev.Catalog, now time.Time) ([]match.Finding, error) {
	scans, err := e.store.LoadCodeScans()
	if err != nil {
		return nil, err
	}
	var out []match.Finding
	var cves []string
	for _, s := range scans {
		for _, f := range s.Findings {
			out = append(out, f)
			cves = append(cves, f.Aliases...)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	slices.Sort(cves)
	match.RescoreDependencies(out, cat, e.epssScores(ctx, slices.Compact(cves)), now)
	return out, nil
}

// mergeLeaks adds secrets from the Git history that the working tree scan
// did not already report in the same file.
func mergeLeaks(tree, hist []leaks.Leak) []leaks.Leak {
	seen := map[string]bool{}
	for _, l := range tree {
		seen[l.Fingerprint+"|"+l.File] = true
	}
	out := slices.Clone(tree)
	for _, l := range hist {
		if !seen[l.Fingerprint+"|"+l.File] {
			seen[l.Fingerprint+"|"+l.File] = true
			out = append(out, l)
		}
	}
	return out
}
