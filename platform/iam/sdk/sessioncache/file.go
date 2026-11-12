// Package sessioncache provides optional storage backends for the IAM SDK's
// SessionCache interface. Importing the core SDK does not enable persistence
// or depend on this package. Backends handle opaque credential records; the
// SDK retains ownership of session identity, proof keys, and refresh policy.
package sessioncache

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// Bound disk reads independently of the SDK's record validation.
const (
	maxFileSize = 1024 * 1024
	maxFileAge  = 24 * time.Hour
	// Isolate records from earlier builds that used per-key locks.
	recordPrefix = "v2-"
	lockName     = "cache-v2.lock"
	tempPrefix   = ".session-v2-"
)

// File implements the SDK's SessionCache interface using a private directory.
// All instances and processes using that directory share one kernel lock.
// The directory must be 0700 and files must be 0600. Symlinks are rejected.
// Daily best-effort cleanup removes unused records older than 24 hours.
// File is safe for concurrent use; transactions for different keys serialize.
type File struct {
	directory string
}

// NewFile creates a lazy filesystem backend. No I/O occurs until Update.
// The caller chooses the directory; this package reads no configuration or
// environment variables. Use with motiveiq.WithSessionCache(NewFile(path)).
func NewFile(directory string) *File {
	return &File{directory: directory}
}

// Update locks the directory across the read, callback, replacement and cleanup.
// A crashed process releases the lock. The single lock file is never unlinked,
// which would let concurrent processes lock different inodes for the same cache.
// Keys must be SHA-256 hex strings, as supplied by the SDK.
func (c *File) Update(ctx context.Context, key string, update func([]byte) ([]byte, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key) != 64 {
		return fmt.Errorf("session cache key must be a SHA-256 hex string")
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("session cache key must be a SHA-256 hex string")
	}
	if err := os.MkdirAll(c.directory, 0o700); err != nil {
		return fmt.Errorf("create session cache: %w", err)
	}
	if err := checkPath(c.directory, true); err != nil {
		return err
	}
	path := filepath.Join(c.directory, recordPrefix+key+".json")
	lockPath := filepath.Join(c.directory, lockName)
	if err := checkPath(lockPath, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	defer lock.Close()
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock session cache: %w", err)
	}
	if !locked {
		return fmt.Errorf("lock session cache: lock not acquired")
	}
	if err := checkPath(lockPath, false); err != nil {
		return err
	}
	current, err := read(path)
	if err != nil {
		return err
	}
	next, err := update(current)
	if err != nil {
		return err
	}
	if next != nil {
		if err := write(path, next); err != nil {
			return err
		}
	}
	c.collect(ctx, lockPath, path, time.Now())
	return nil
}

// collect runs only under the directory lock. Its mtime records the last GC
// attempt across processes without another state file or a background worker.
// Eviction never decodes credentials; even a valid evicted record is just a miss.
func (c *File) collect(ctx context.Context, lockPath, currentPath string, now time.Time) {
	info, err := os.Stat(lockPath)
	if err != nil || now.Sub(info.ModTime()) < maxFileAge || ctx.Err() != nil {
		return
	}
	// Throttle failed attempts too. Never replace the lock file's inode.
	if err := os.Chtimes(lockPath, now, now); err != nil {
		return
	}
	entries, err := os.ReadDir(c.directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		key := strings.TrimSuffix(strings.TrimPrefix(name, recordPrefix), ".json")
		_, keyErr := hex.DecodeString(key)
		record := name == recordPrefix+key+".json" && len(key) == 64 && keyErr == nil
		temporary := strings.HasPrefix(name, tempPrefix) && strings.HasSuffix(name, ".tmp")
		path := filepath.Join(c.directory, name)
		if (!record && !temporary) || path == currentPath {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() && info.ModTime().Before(now.Add(-maxFileAge)) {
			_ = os.Remove(path)
		}
	}
}

// Filesystem errors fail explicitly instead of silently disabling persistence.
// Credential-store parents are never chmodded by this dedicated cache.
func checkPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if directory {
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return fmt.Errorf("session cache directory %s must be a directory with permissions 0700", path)
		}
	} else if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("session cache file %s must be a regular file with permissions 0600", path)
	}
	return nil
}

func read(path string) ([]byte, error) {
	if err := checkPath(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open session cache: %w", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read session cache: %w", err)
	}
	if len(payload) > maxFileSize {
		return nil, nil
	}
	return payload, nil
}

func write(path string, payload []byte) error {
	if len(payload) > maxFileSize {
		return fmt.Errorf("session cache record exceeds size limit")
	}
	file, err := os.CreateTemp(filepath.Dir(path), tempPrefix+"*.tmp")
	if err != nil {
		return fmt.Errorf("create session cache entry: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect session cache entry: %w", err)
	}
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write session cache entry: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync session cache entry: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close session cache entry: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("replace session cache entry: %w", err)
	}
	return nil
}
