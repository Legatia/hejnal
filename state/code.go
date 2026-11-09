package state

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Legatia/hejnal/match"
)

// CodeDir holds saved code scans, one file per project.
const CodeDir = "code"

// CodeScan is a saved scan of a project's dependencies, secrets and
// infrastructure code, and of its container images.
type CodeScan struct {
	ScannedAt time.Time `json:"scannedAt"`
	Project   string    `json:"project"`
	// Packages and Files count what was checked: packages in lockfiles and
	// images, and infrastructure files with something to check.
	Packages int      `json:"packages"`
	Images   []string `json:"images,omitempty"`
	Parts    []string `json:"parts"`
	Notes    []string `json:"notes,omitempty"`
	// Findings never hold a secret, only its redacted form and fingerprint.
	Findings []match.Finding `json:"findings"`
}

var projectRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ProjectFile is the file name a project's scan is saved under.
func ProjectFile(project string) string {
	name := strings.Trim(projectRE.ReplaceAllString(project, "-"), "-.")
	if name == "" {
		name = "project"
	}
	if len(name) > 100 {
		name = name[:100]
	}
	return name + ".json"
}

// SaveCodeScan stores a project's scan, replacing its previous one.
func (s Store) SaveCodeScan(scan *CodeScan) error {
	dir := filepath.Join(s.Dir, CodeDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return WriteJSON(filepath.Join(dir, ProjectFile(scan.Project)), scan)
}

// LoadCodeScans reads every saved code scan.
func (s Store) LoadCodeScans() ([]*CodeScan, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, CodeDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*CodeScan
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var scan CodeScan
		if err := readJSON(filepath.Join(s.Dir, CodeDir, e.Name()), &scan); err != nil {
			return nil, err
		}
		out = append(out, &scan)
	}
	return out, nil
}
