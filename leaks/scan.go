package leaks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// binarySniff is how much of a file is checked for a NUL byte, which marks a
// binary file.
const binarySniff = 8 << 10

// ScanReader scans text from r line by line and reports leaks with File set
// to name. Very long lines are scanned in overlapping pieces, so memory use
// stays bounded. Options only choose which files ScanDir and ScanGitHistory
// read, so ScanReader scans everything it is given. If reading fails,
// ScanReader returns the leaks found so far together with the error.
func ScanReader(name string, r io.Reader, opts Options) ([]Leak, error) {
	s := &lineScanner{file: name}
	if err := s.read(r); err != nil {
		return finish(s.leaks), fmt.Errorf("leaks: read %s: %w", name, err)
	}
	return finish(s.leaks), nil
}

// ScanDir scans the files under root, which may also be a single file. It
// does not follow symbolic links, and skips binary files, files larger than
// Options.MaxFileSize, lockfiles and the directories in Options.SkipDirs.
// Leak.File is the path relative to root, with forward slashes.
//
// Files and directories that cannot be read are skipped, and the error then
// says how many there were; the leaks found are still returned. If ctx ends,
// ScanDir stops and returns only ctx's error.
func ScanDir(ctx context.Context, root string, opts Options) ([]Leak, error) {
	opts = opts.withDefaults()
	info, err := os.Lstat(root)
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		// The root was named on purpose, so it is the one link followed.
		if root, err = filepath.EvalSymlinks(root); err == nil {
			info, err = os.Lstat(root)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("leaks: %w", err)
	}
	if !info.IsDir() {
		leaks, err := scanFile(root, filepath.Base(root), opts.MaxFileSize)
		if err != nil {
			return nil, fmt.Errorf("leaks: %w", err)
		}
		return finish(leaks), nil
	}

	var all []Leak
	var unreadable []error
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if path == root {
				return err
			}
			unreadable = append(unreadable, err)
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if path != root && opts.skipDir(d.Name(), rel) {
				return fs.SkipDir
			}
			return nil
		}
		// Symbolic links, sockets, devices and named pipes are not files to
		// scan; opening a named pipe could block for ever.
		if !d.Type().IsRegular() || lockfiles[d.Name()] {
			return nil
		}
		leaks, err := scanFile(path, rel, opts.MaxFileSize)
		if err != nil {
			unreadable = append(unreadable, err)
			return nil
		}
		all = append(all, leaks...)
		return nil
	})
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr
	}
	if walkErr != nil {
		return nil, fmt.Errorf("leaks: %w", walkErr)
	}
	all = finish(all)
	if len(unreadable) > 0 {
		return all, fmt.Errorf("leaks: skipped %d unreadable files or directories, the first: %w", len(unreadable), unreadable[0])
	}
	return all, nil
}

// scanFile scans one regular file, reporting it under the name rel. Binary
// and oversized files are skipped without an error.
func scanFile(path, rel string, maxSize int64) ([]Leak, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxSize {
		return nil, nil
	}
	head := make([]byte, binarySniff)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	head = head[:n]
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, nil
	}
	// The limit holds even if the file grows while it is read.
	s := &lineScanner{file: rel}
	if err := s.read(io.MultiReader(bytes.NewReader(head), io.LimitReader(f, maxSize-int64(n)))); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s.leaks, nil
}
