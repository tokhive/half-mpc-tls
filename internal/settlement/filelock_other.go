//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package settlement

import (
	"errors"
	"os"
)

var errFileLockUnsupported = errors.New("settlement journal file locking is unsupported on this platform")

func lockFile(_ *os.File) error {
	return errFileLockUnsupported
}

func unlockFile(_ *os.File) error {
	return nil
}
