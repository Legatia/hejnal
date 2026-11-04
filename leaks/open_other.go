//go:build !unix

package leaks

import "os"

// openFile opens a file for scanning. skip is true when path is not a
// regular file. Without O_NOFOLLOW, a file swapped for a link between this
// check and the open is still followed.
func openFile(path string) (f *os.File, skip bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, nil
	}
	f, err = os.Open(path)
	return f, false, err
}
