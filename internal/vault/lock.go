package vault

import (
	"fmt"
	"os"
	"syscall"
)

// FileLock provides advisory file locking for vault operations.
type FileLock struct {
	path string
	file *os.File
}

// Lock acquires an exclusive lock on the vault file.
func Lock(vaultPath string) (*FileLock, error) {
	lockPath := vaultPath + ".lock"

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating lock file: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("vault is locked by another process (remove %s if stale)", lockPath)
	}

	return &FileLock{path: lockPath, file: f}, nil
}

// Unlock releases the lock and removes the lock file.
func (fl *FileLock) Unlock() {
	if fl.file != nil {
		syscall.Flock(int(fl.file.Fd()), syscall.LOCK_UN)
		fl.file.Close()
		os.Remove(fl.path)
	}
}
