//go:build unix

package leaks

import (
	"errors"
	"os"
	"syscall"
)

// openFile opens a file for scanning without following a symbolic link and
// without blocking on a named pipe, in case the file was swapped after its
// directory was listed. skip is true when path is no longer a regular file.
func openFile(path string) (f *os.File, skip bool, err error) {
	f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, true, nil
	}
	return f, false, err
}
