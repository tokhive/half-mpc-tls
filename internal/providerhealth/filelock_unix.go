//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package providerhealth

import (
	"os"
	"syscall"
)

func lockProviderHealthFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockProviderHealthFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
