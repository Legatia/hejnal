// Package container finds the packages in a container image: the
// distribution's packages (Debian, Ubuntu, Alpine), the modules compiled
// into Go programs, installed Python and Node.js packages, and any lockfile
// the image carries.
//
// It reads an image saved with `docker save` or `podman save`, or an OCI
// image layout as a directory or a tar archive, without Docker and without
// running anything in the image. Layers are applied in order, so files a
// later layer deletes do not count.
package container

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Legatia/hejnal/deps"
)

// Image is what was found in one image.
type Image struct {
	// Name is the image's name and tag, if the archive records one.
	Name string `json:"name,omitempty"`
	// OS is the distribution, such as "Debian:12", or "" if Hejnal cannot
	// match its packages.
	OS       string         `json:"os,omitempty"`
	OSName   string         `json:"osName,omitempty"`
	Packages []deps.Package `json:"packages"`
	// Notes say what could not be read.
	Notes []string `json:"notes,omitempty"`
}

// Limits on what one image may make Hejnal read.
const (
	maxSmallFile = 64 << 20  // package databases and lockfiles
	maxBinary    = 256 << 20 // programs checked for Go build information
	maxLayers    = 256
)

// layer is what one layer adds and deletes.
type layer struct {
	files      map[string][]byte         // small files of interest
	packages   map[string][]deps.Package // packages found in a file, by path
	deleted    []string                  // paths whiteouts delete
	opaque     []string                  // directories whose earlier contents go
	unreadable string
}

// interesting reports whether a file's content matters, and whether it is
// small enough to keep whole.
func interesting(p string) (keep, program bool) {
	switch p {
	case "etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed":
		return true, false
	}
	switch {
	case strings.HasPrefix(p, "var/lib/dpkg/status.d/"):
		return true, false
	case strings.HasSuffix(p, ".dist-info/METADATA"), strings.HasSuffix(p, ".egg-info/PKG-INFO"):
		return true, false
	case strings.Contains(p, "node_modules/") && strings.HasSuffix(p, "/package.json"):
		return true, false
	case deps.Lockfile(p) && !strings.Contains(p, "node_modules/"):
		return true, false
	}
	return false, true
}

func readLayer(r io.Reader) (*layer, error) {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return readTar(gz)
	}
	if magic, _ := br.Peek(4); bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return &layer{unreadable: "a layer is compressed with zstd, which Hejnal cannot read; save the image with gzip or uncompressed layers"}, nil
	}
	return readTar(br)
}

func readTar(r io.Reader) (*layer, error) {
	l := &layer{files: map[string][]byte{}, packages: map[string][]deps.Package{}}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return l, nil
		}
		if err != nil {
			return nil, err
		}
		p := clean(h.Name)
		if p == "" {
			continue
		}
		dir, base := path.Split(p)
		if base == ".wh..wh..opq" {
			l.opaque = append(l.opaque, strings.TrimSuffix(dir, "/"))
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			l.deleted = append(l.deleted, dir+strings.TrimPrefix(base, ".wh."))
			continue
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		keep, program := interesting(p)
		switch {
		case keep && h.Size <= maxSmallFile:
			data, err := io.ReadAll(io.LimitReader(tr, maxSmallFile))
			if err != nil {
				return nil, err
			}
			l.files[p] = data
		case program && h.Mode&0o111 != 0 && h.Size > 4 && h.Size <= maxBinary:
			if pkgs := goModules(tr, h.Size, p); pkgs != nil {
				l.packages[p] = pkgs
			}
		}
	}
}

// goModules reads the modules compiled into a Go program, or nil if the
// file is not one.
func goModules(r io.Reader, size int64, p string) []deps.Package {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(4); !bytes.Equal(magic, []byte("\x7fELF")) {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(br, size))
	if err != nil {
		return nil
	}
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	file := "/" + p
	out := []deps.Package{{Ecosystem: deps.Go, Name: "stdlib", Version: strings.TrimPrefix(strings.Fields(bi.GoVersion + " ")[0], "go"), File: file}}
	for _, m := range bi.Deps {
		if m.Replace != nil {
			m = m.Replace
		}
		out = append(out, deps.Package{Ecosystem: deps.Go, Name: m.Path, Version: strings.TrimPrefix(m.Version, "v"), File: file})
	}
	return out
}

// clean makes a tar entry name a path inside the image, or "" if it
// leaves it.
func clean(name string) string {
	p := path.Clean("/" + strings.ReplaceAll(name, "\\", "/"))
	if p == "/" {
		return ""
	}
	return strings.TrimPrefix(p, "/")
}

// apply merges the layers, last one winning, and returns the files and
// packages of the finished image.
func apply(layers []*layer) (map[string][]byte, map[string][]deps.Package, []string) {
	files := map[string][]byte{}
	pkgs := map[string][]deps.Package{}
	var notes []string
	under := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") || dir == "" }
	for _, l := range layers {
		if l.unreadable != "" {
			notes = append(notes, l.unreadable)
			continue
		}
		for _, dir := range l.opaque {
			for p := range files {
				if under(p, dir) && p != dir {
					delete(files, p)
				}
			}
			for p := range pkgs {
				if under(p, dir) && p != dir {
					delete(pkgs, p)
				}
			}
		}
		for _, d := range l.deleted {
			for p := range files {
				if under(p, d) {
					delete(files, p)
				}
			}
			for p := range pkgs {
				if under(p, d) {
					delete(pkgs, p)
				}
			}
		}
		for p, data := range l.files {
			files[p] = data
		}
		for p, ps := range l.packages {
			pkgs[p] = ps
		}
	}
	return files, pkgs, notes
}

// Read reads an image from a `docker save` archive, an OCI archive or an
// OCI layout directory.
func Read(ctx context.Context, src string) (*Image, error) {
	st, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	var layers []*layer
	var name string
	if st.IsDir() {
		layers, name, err = readLayoutDir(ctx, src)
	} else {
		layers, name, err = readArchive(ctx, src)
	}
	if err != nil {
		return nil, err
	}
	files, pkgs, notes := apply(layers)
	img := &Image{Name: name, Notes: notes}
	img.analyse(files, pkgs)
	return img, nil
}

// readArchive reads an image tarball in one pass: layers are read as they
// come, and put in order once the manifest says which is which.
func readArchive(ctx context.Context, src string) ([]*layer, string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	byName := map[string]*layer{}
	small := map[string][]byte{}
	tr := tar.NewReader(bufio.NewReader(f))
	for {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("%s is not an image archive: %w", filepath.Base(src), err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		n := clean(h.Name)
		switch {
		case n == "manifest.json" || n == "index.json" || n == "oci-layout" || (strings.HasPrefix(n, "blobs/") && h.Size < 4<<20 && !strings.HasSuffix(n, "layer.tar")):
			data, err := io.ReadAll(io.LimitReader(tr, 4<<20))
			if err != nil {
				return nil, "", err
			}
			// A small blob may be a manifest or a small layer; keep both
			// readings.
			small[n] = data
			if strings.HasPrefix(n, "blobs/") {
				if l, err := readLayer(bytes.NewReader(data)); err == nil {
					byName[n] = l
				}
			}
		case strings.HasSuffix(n, "layer.tar") || strings.HasPrefix(n, "blobs/"):
			l, err := readLayer(tr)
			if err != nil {
				// Not every blob is a layer; the manifest says which are.
				continue
			}
			byName[n] = l
		}
	}
	return orderLayers(small, byName, func(n string) ([]byte, bool) { d, ok := small[n]; return d, ok })
}

func readLayoutDir(ctx context.Context, dir string) ([]*layer, string, error) {
	read := func(n string) ([]byte, bool) {
		data, err := readFileLimited(filepath.Join(dir, filepath.FromSlash(n)), 4<<20)
		return data, err == nil
	}
	small := map[string][]byte{}
	for _, n := range []string{"manifest.json", "index.json"} {
		if d, ok := read(n); ok {
			small[n] = d
		}
	}
	names, imgName, err := layerNames(small, read)
	if err != nil {
		return nil, "", err
	}
	byName := map[string]*layer{}
	for _, n := range names {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return nil, "", err
		}
		l, err := readLayer(f)
		f.Close()
		if err != nil {
			return nil, "", fmt.Errorf("layer %s: %w", n, err)
		}
		byName[n] = l
	}
	return pick(names, byName), imgName, nil
}

func readFileLimited(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

func orderLayers(small map[string][]byte, byName map[string]*layer, read func(string) ([]byte, bool)) ([]*layer, string, error) {
	names, name, err := layerNames(small, read)
	if err != nil {
		return nil, "", err
	}
	return pick(names, byName), name, nil
}

func pick(names []string, byName map[string]*layer) []*layer {
	var out []*layer
	for _, n := range names {
		if l, ok := byName[n]; ok {
			out = append(out, l)
		} else {
			out = append(out, &layer{unreadable: "layer " + path.Base(n) + " is missing from the archive or could not be read"})
		}
	}
	return out
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// layerNames returns the archive paths of the image's layers, bottom
// first, and its name.
func layerNames(small map[string][]byte, read func(string) ([]byte, bool)) ([]string, string, error) {
	if data, ok := small["manifest.json"]; ok {
		var m []struct {
			RepoTags []string `json:"RepoTags"`
			Layers   []string `json:"Layers"`
		}
		if err := json.Unmarshal(data, &m); err == nil && len(m) > 0 {
			if len(m[0].Layers) > maxLayers {
				return nil, "", errors.New("too many layers")
			}
			name := ""
			if len(m[0].RepoTags) > 0 {
				name = m[0].RepoTags[0]
			}
			var out []string
			for _, l := range m[0].Layers {
				if c := clean(l); c != "" {
					out = append(out, c)
				}
			}
			return out, name, nil
		}
	}
	data, ok := small["index.json"]
	if !ok {
		return nil, "", errors.New("no manifest.json or index.json: not an image saved with docker save or in OCI layout")
	}
	blob := func(digest string) ([]byte, error) {
		if !digestRE.MatchString(digest) {
			return nil, fmt.Errorf("invalid digest %q", digest)
		}
		n := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
		if d, ok := small[n]; ok {
			return d, nil
		}
		if d, ok := read(n); ok {
			return d, nil
		}
		return nil, fmt.Errorf("blob %s missing", digest)
	}
	type desc struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Annotations map[string]string `json:"annotations"`
		Platform    *struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	}
	var doc struct {
		Manifests []desc `json:"manifests"`
		Layers    []desc `json:"layers"`
	}
	name := ""
	for depth := 0; depth < 4; depth++ {
		doc.Manifests, doc.Layers = nil, nil
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, "", fmt.Errorf("index: %w", err)
		}
		if len(doc.Layers) > 0 {
			if len(doc.Layers) > maxLayers {
				return nil, "", errors.New("too many layers")
			}
			var out []string
			for _, l := range doc.Layers {
				if !digestRE.MatchString(l.Digest) {
					return nil, "", fmt.Errorf("invalid layer digest %q", l.Digest)
				}
				out = append(out, "blobs/sha256/"+strings.TrimPrefix(l.Digest, "sha256:"))
			}
			return out, name, nil
		}
		if len(doc.Manifests) == 0 {
			break
		}
		// Prefer linux/amd64 in a multi-platform index, else the first.
		chosen := doc.Manifests[0]
		for _, m := range doc.Manifests {
			if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
				chosen = m
				break
			}
		}
		if n := chosen.Annotations["io.containerd.image.name"]; n != "" && name == "" {
			name = n
		} else if n := chosen.Annotations["org.opencontainers.image.ref.name"]; n != "" && name == "" {
			name = n
		}
		var err error
		if data, err = blob(chosen.Digest); err != nil {
			return nil, "", err
		}
	}
	return nil, "", errors.New("the image's manifest lists no layers")
}

// analyse turns the image's files into packages.
func (img *Image) analyse(files map[string][]byte, found map[string][]deps.Package) {
	osRelease := files["etc/os-release"]
	if osRelease == nil {
		osRelease = files["usr/lib/os-release"]
	}
	id, versionID, pretty, lts := parseOSRelease(osRelease)
	img.OSName = pretty
	switch id {
	case "debian":
		if major, _, _ := strings.Cut(versionID, "."); major != "" {
			img.OS = "Debian:" + major
		}
	case "ubuntu":
		if versionID != "" {
			img.OS = "Ubuntu:" + versionID
			if lts {
				img.OS += ":LTS"
			}
		}
	case "alpine":
		f := strings.Split(versionID, ".")
		if len(f) >= 2 {
			img.OS = "Alpine:v" + f[0] + "." + f[1]
		}
	}
	var pkgs []deps.Package
	distro := false
	for p, data := range files {
		switch {
		case p == "var/lib/dpkg/status" || strings.HasPrefix(p, "var/lib/dpkg/status.d/"):
			distro = true
			if strings.HasPrefix(img.OS, "Debian") || strings.HasPrefix(img.OS, "Ubuntu") {
				pkgs = append(pkgs, parseDpkg(data, img.OS, "/"+p)...)
			}
		case p == "lib/apk/db/installed":
			distro = true
			if strings.HasPrefix(img.OS, "Alpine") {
				pkgs = append(pkgs, parseApk(data, img.OS, "/"+p)...)
			}
		case strings.HasSuffix(p, "/METADATA") || strings.HasSuffix(p, "/PKG-INFO"):
			if n, v := pyMetadata(data); n != "" {
				pkgs = append(pkgs, deps.Package{Ecosystem: deps.PyPI, Name: pyName(n), Version: v, File: "/" + path.Dir(p)})
			}
		case strings.HasSuffix(p, "/package.json"):
			var pj struct{ Name, Version string }
			if json.Unmarshal(data, &pj) == nil && pj.Name != "" {
				pkgs = append(pkgs, deps.Package{Ecosystem: deps.Npm, Name: pj.Name, Version: pj.Version, File: "/" + path.Dir(p)})
			}
		case deps.Lockfile(p):
			if ps, err := deps.Parse("/"+p, data); err == nil {
				pkgs = append(pkgs, ps...)
			}
		}
	}
	for _, ps := range found {
		pkgs = append(pkgs, ps...)
	}
	if distro && img.OS == "" {
		what := pretty
		if what == "" {
			what = "this distribution"
		}
		img.Notes = append(img.Notes, "the packages of "+what+" were not checked: Hejnal reads Debian, Ubuntu and Alpine package databases")
	}
	// Parse once more through deps so names and versions are checked the
	// same way as a project's.
	img.Packages = cleanPackages(pkgs)
}

func cleanPackages(pkgs []deps.Package) []deps.Package {
	var out []deps.Package
	for _, p := range pkgs {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Version) == "" || strings.ContainsAny(p.Version, " /<>=^~*|") {
			continue
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b deps.Package) int {
		if c := strings.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.File, b.File)
	})
	return slices.CompactFunc(out, func(a, b deps.Package) bool {
		return a.Ecosystem == b.Ecosystem && a.Name == b.Name && a.Version == b.Version && a.File == b.File
	})
}

func parseOSRelease(data []byte) (id, versionID, pretty string, lts bool) {
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = strings.ToLower(v)
		case "VERSION_ID":
			versionID = v
		case "PRETTY_NAME":
			pretty = v
		case "VERSION":
			lts = strings.Contains(v, "LTS")
		}
	}
	return
}

// parseDpkg reads dpkg's status file: installed packages, named by their
// source package, which is what Debian and Ubuntu advisories name.
func parseDpkg(data []byte, eco, file string) []deps.Package {
	var out []deps.Package
	for _, stanza := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n") {
		f := map[string]string{}
		for _, line := range strings.Split(stanza, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if ok {
				f[k] = strings.TrimSpace(v)
			}
		}
		if f["Package"] == "" || f["Version"] == "" {
			continue
		}
		if st := f["Status"]; st != "" && !strings.HasSuffix(st, " installed") {
			continue
		}
		name, version := f["Package"], f["Version"]
		if src := f["Source"]; src != "" {
			s := strings.Fields(src)
			name = s[0]
			if len(s) > 1 {
				version = strings.Trim(s[1], "()")
			}
		}
		out = append(out, deps.Package{Ecosystem: eco, Name: name, Version: version, Binary: f["Package"], File: file})
	}
	return out
}

// parseApk reads Alpine's installed database; advisories name the origin
// package.
func parseApk(data []byte, eco, file string) []deps.Package {
	var out []deps.Package
	for _, rec := range strings.Split(string(data), "\n\n") {
		f := map[byte]string{}
		for _, line := range strings.Split(rec, "\n") {
			if len(line) > 2 && line[1] == ':' {
				f[line[0]] = line[2:]
			}
		}
		if f['P'] == "" || f['V'] == "" {
			continue
		}
		name := f['P']
		if f['o'] != "" {
			name = f['o']
		}
		out = append(out, deps.Package{Ecosystem: eco, Name: name, Version: f['V'], Binary: f['P'], File: file})
	}
	return out
}

func pyMetadata(data []byte) (name, version string) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // the headers end at the first blank line
		}
		if v, ok := strings.CutPrefix(line, "Name: "); ok {
			name = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Version: "); ok {
			version = strings.TrimSpace(v)
		}
	}
	return
}

var pySep = regexp.MustCompile(`[-_.]+`)

func pyName(s string) string {
	return pySep.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
}
