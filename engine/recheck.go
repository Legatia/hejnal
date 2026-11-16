package engine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Legatia/hejnal/match"
	"github.com/Legatia/hejnal/state"
)

// What a fresh look says about one item of the fix list.
const (
	// ItemFound: the fresh look finds the item.
	ItemFound = "found"
	// ItemGone: the item was found before, and the fresh look, which
	// covers where it was, does not find it.
	ItemGone = "gone"
	// ItemMoved: the item is not found under its ID, but the same thing is
	// found under another: a package upgraded to a version that still has
	// an advisory, or a resource moved to another file. Now holds it.
	ItemMoved = "moved"
	// ItemNotFound: the fresh look does not find the item, and nothing on
	// record says it was ever found, so the ID may be another project's
	// or mistyped.
	ItemNotFound = "not_found"
	// ItemUnknown: the fresh look cannot tell, for the reason in Why.
	ItemUnknown = "unknown"
)

// Recheck is what a fresh look says about one item.
type Recheck struct {
	ID     string
	Status string
	// Group is the item as the fresh look found it or, when it did not, as
	// it was last found. It is nil when nothing on record names the ID.
	Group *match.Group
	// Now is the item that took this one's place, when the status is
	// ItemMoved.
	Now *match.Group
	// Why says why the status is ItemUnknown.
	Why string
}

// ValidItemID reports whether id has the form of an item's ID.
func ValidItemID(id string) bool {
	return len(id) == len(match.ItemID("")) && strings.Trim(id, "0123456789abcdef") == ""
}

// FindItem returns the item with the ID among the findings, or nil.
func FindItem(fs []match.Finding, id string) *match.Group {
	for _, g := range match.Groups(fs) {
		if g.ID() == id {
			return &g
		}
	}
	return nil
}

// Known returns the findings the state directory holds: those of the last
// run, and those of code scans saved since. A recheck reads from them
// where an item was found. They are none before anything was saved.
func Known(store state.Store) ([]match.Finding, error) {
	var out []match.Finding
	snap, err := store.LoadFindings()
	switch {
	case err == nil:
		out = append(out, snap.Findings...)
	case !errors.Is(err, state.ErrNoFindings):
		return nil, err
	}
	scans, err := store.LoadCodeScans()
	if err != nil {
		return nil, err
	}
	for _, s := range scans {
		out = append(out, s.Findings...)
	}
	return out, nil
}

// RecheckCode says whether a code scan still finds an item. req is what
// the scan was asked for. known are findings on record, such as the saved
// ones: they tell where the item was found, so a scan of another project
// or directory, or one that left out the part that finds the item, is
// never taken for a fix.
//
// keyed says the scan made its secret fingerprints with the key the known
// findings were made with. A secret's ID comes from its fingerprint, so
// without the same key a known secret cannot be told gone.
func RecheckCode(id string, scan *state.CodeScan, req CodeRequest, known []match.Finding, keyed bool) Recheck {
	r := Recheck{ID: id}
	active := match.Active(scan.Findings)
	if g := FindItem(active, id); g != nil {
		r.Status, r.Group = ItemFound, g
		return r
	}
	unknown := func(format string, args ...any) Recheck {
		r.Status, r.Why = ItemUnknown, fmt.Sprintf(format, args...)
		return r
	}
	ran := func(part string) bool { return slices.Contains(scan.Parts, part) }
	unreadable := ""
	for _, n := range scan.Notes {
		if strings.HasPrefix(n, "could not read ") {
			unreadable = n
			break
		}
	}
	prior := FindItem(known, id)
	if prior == nil {
		switch {
		case !ran(PartDeps) || !ran(PartSecrets) || !ran(PartIaC):
			return unknown("the scan left out a part (it ran: %s), and nothing on record says which part finds this item", strings.Join(scan.Parts, ", "))
		case unreadable != "":
			return unknown("the scan %s, and nothing on record says where this item was found", unreadable)
		}
		r.Status = ItemNotFound
		return r
	}
	r.Group = prior

	// Where the item was found: files in the scanned directories, and
	// images, whose files are named "image:path".
	var files, images []string
	for _, f := range prior.Findings {
		switch {
		case f.File == "" || f.Commit != "":
		case prior.Kind == match.KindDependency && strings.Contains(f.File, ":"):
			if !slices.Contains(images, f.File) {
				images = append(images, f.File)
			}
		case !slices.Contains(files, f.File):
			files = append(files, f.File)
		}
	}
	switch prior.Kind {
	case match.KindDependency:
		switch {
		case len(files) > 0 && !ran(PartDeps):
			return unknown("the scan did not check dependencies")
		case unreadable != "":
			return unknown("the scan %s", unreadable)
		}
		for _, file := range images {
			if !slices.ContainsFunc(scan.Images, func(name string) bool { return strings.HasPrefix(file, name+":") }) {
				return unknown("the item was found in a container image (%s), which this scan did not check", file)
			}
		}
	case match.KindSecret:
		switch {
		case !ran(PartSecrets):
			return unknown("the scan did not look for secrets")
		case !keyed:
			return unknown("the item is a secret, and this scan could not use the key in the state directory that secret IDs are made with")
		case len(files) == 0 && !req.History:
			return unknown("the secret was found in the Git history, which this scan did not read")
		}
	case match.KindMisconfig:
		if !ran(PartIaC) {
			return unknown("the scan did not check infrastructure code")
		}
	default:
		return unknown("a code scan does not find this item: it is on %s, which a live check or the next run looks at", itemPlace(prior))
	}
	// A secret's ID is the same in every project; the others name theirs.
	if prior.Kind != match.KindSecret && prior.Host != scan.Project {
		return unknown("the item was found in project %q, and this scan is of project %q", prior.Host, scan.Project)
	}
	if len(files) > 0 {
		if !slices.ContainsFunc(files, func(f string) bool { return !req.excludes(f) }) {
			return unknown("the scan excluded %s, where the item was found", strings.Join(files, ", "))
		}
		// A scan run in another directory finds nothing, and that is no
		// fix. A lockfile is still there after an upgrade; another file
		// may be deleted to fix the item, so then any other file on
		// record for the project shows the directory is the right one.
		here := slices.ContainsFunc(files, req.has)
		if !here && prior.Kind != match.KindDependency {
			here = slices.ContainsFunc(known, func(f match.Finding) bool {
				return f.Host == scan.Project && f.File != "" && f.Commit == "" && !slices.Contains(files, f.File) && req.has(f.File)
			})
		}
		if !here {
			return unknown("%s, where the item was found, is not in what was scanned: run the scan on the directory the item names", strings.Join(files, ", "))
		}
	}
	// The same thing under another ID is not a fix: a package upgraded to
	// a version that still has an advisory, a resource moved to another
	// file.
	for _, g := range match.Groups(active) {
		if g.Kind != prior.Kind || g.Host != prior.Host || g.Technology != prior.Technology {
			continue
		}
		switch prior.Kind {
		case match.KindDependency:
			if g.Findings[0].Ecosystem != prior.Findings[0].Ecosystem {
				continue
			}
		case match.KindMisconfig:
			if g.TechID != prior.TechID {
				continue
			}
		default:
			continue
		}
		if FindItem(known, g.ID()) != nil {
			// It was on record beside this item, so it is another one.
			continue
		}
		r.Status, r.Now = ItemMoved, &g
		return r
	}
	r.Status = ItemGone
	return r
}

// rel returns the file's path under one of the scanned directories, the
// way ScanCode names files: with several directories, each file's name
// starts with its directory's.
func (req CodeRequest) rel(file string) (root, rel string, ok bool) {
	for _, dir := range req.Dirs {
		root, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		rel := file
		if len(req.Dirs) > 1 {
			if rel, ok = strings.CutPrefix(file, filepath.Base(root)+"/"); !ok {
				continue
			}
		}
		if filepath.IsLocal(filepath.FromSlash(rel)) {
			return root, rel, true
		}
	}
	return "", "", false
}

// has reports whether the file a finding names is in the scanned
// directories.
func (req CodeRequest) has(file string) bool {
	root, rel, ok := req.rel(file)
	if !ok {
		return false
	}
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

// excludes reports whether the scan left out the file a finding names.
func (req CodeRequest) excludes(file string) bool {
	_, rel, ok := req.rel(file)
	return ok && excluded(rel, req.Exclude)
}

// RecheckLive says whether a live check of the targets still finds an
// item. found is what the check found; known are findings on record, which
// tell where the item was found, so a check of another system, or one
// without the part that finds the item, is never taken for a fix. checks
// says whether the check asked for the fixed paths and product versions.
func RecheckLive(id string, found, known []match.Finding, targets []LiveTarget, checks bool) Recheck {
	r := Recheck{ID: id}
	if g := FindItem(match.Active(found), id); g != nil {
		r.Status, r.Group = ItemFound, g
		return r
	}
	unknown := func(format string, args ...any) Recheck {
		r.Status, r.Why = ItemUnknown, fmt.Sprintf(format, args...)
		return r
	}
	prior := FindItem(known, id)
	if prior == nil {
		r.Status = ItemNotFound
		return r
	}
	r.Group = prior
	switch prior.Kind {
	case match.KindDependency, match.KindMisconfig, match.KindSecret:
		return unknown("the item is in code, not on a live system: a code scan checks it")
	case match.KindEmail, match.KindBreach, match.KindTakeover:
		return unknown("a live check does not look at mail records, data breaches or names left pointing at a hosting service: the next run does")
	}
	if !slices.ContainsFunc(targets, func(t LiveTarget) bool { return t.Host == prior.Host && (prior.Port == 0 || prior.Port == t.Port) }) {
		return unknown("the item is on %s, which this check did not look at", itemPlace(prior))
	}
	if !checks && prior.Kind != match.KindTLSExpired && prior.Kind != match.KindTLSExpiring {
		return unknown("this check left out the fixed paths and product versions, which may be what found the item")
	}
	r.Status = ItemGone
	return r
}

func itemPlace(g *match.Group) string {
	if g.Port == 0 {
		return g.Host
	}
	return net.JoinHostPort(g.Host, strconv.Itoa(g.Port))
}
