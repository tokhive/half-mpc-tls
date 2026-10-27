//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package providerhealth

import (
	"errors"
	"os"
)

func lockProviderHealthFile(_ *os.File) error {
	return errors.New("Provider health file locking is unsupported")
}

func unlockProviderHealthFile(_ *os.File) error { return nil }
