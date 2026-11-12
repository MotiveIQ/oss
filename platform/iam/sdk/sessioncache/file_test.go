package sessioncache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func store(t *testing.T, cache *File, value []byte) {
	t.Helper()
	if err := cache.Update(t.Context(), testKey, func([]byte) ([]byte, error) { return value, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestFileTransaction(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	cache := NewFile(directory)
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor performed I/O: %v", err)
	}
	calls := 0
	if err := cache.Update(t.Context(), testKey, func(current []byte) ([]byte, error) {
		calls++
		if current != nil {
			t.Fatal("missing entry was not nil")
		}
		return []byte("opaque credential record"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("callback count = %d, want 1", calls)
	}
	if err := checkPath(directory, true); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %d, error %v; want one record and one lock", len(entries), err)
	}
	for _, entry := range entries {
		if err := checkPath(filepath.Join(directory, entry.Name()), false); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(directory, recordPrefix+testKey+".json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// A separate backend instance reads the same opaque bytes. A nil result
	// leaves the file untouched, even if the callback mutates its local copy.
	if err := NewFile(directory).Update(t.Context(), testKey, func(current []byte) ([]byte, error) {
		if string(current) != "opaque credential record" {
			t.Fatal("backend did not preserve opaque bytes")
		}
		current[0] = 'X'
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("cache hit replaced the entry: %v", err)
	}
	failure := errors.New("refresh failed")
	if err := cache.Update(t.Context(), testKey, func([]byte) ([]byte, error) {
		return []byte("uncommitted"), failure
	}); !errors.Is(err, failure) {
		t.Fatalf("callback error was not returned: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "opaque credential record" {
		t.Fatal("unchanged/failed callbacks modified the stored record")
	}
	// The failed callback must also release its lock.
	store(t, cache, []byte("replacement"))
}

func TestFileConcurrentTransactions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	const callers = 16
	errs := make([]error, callers)
	var group sync.WaitGroup
	for i := range callers {
		group.Go(func() {
			errs[i] = NewFile(directory).Update(t.Context(), testKey, func(current []byte) ([]byte, error) {
				value := 0
				if current != nil {
					var err error
					value, err = strconv.Atoi(string(current))
					if err != nil {
						return nil, err
					}
				}
				return []byte(strconv.Itoa(value + 1)), nil
			})
		})
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.Join(directory, recordPrefix+testKey+".json"))
	if err != nil || string(got) != strconv.Itoa(callers) {
		t.Fatalf("lost a concurrent read-modify-write: value %q, error %v", got, err)
	}
}

func TestFileLockCancellation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := flock.New(filepath.Join(directory, lockName), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	called := false
	err := NewFile(directory).Update(ctx, testKey, func([]byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("waiting for lock: error=%v callback=%t", err, called)
	}
}

func TestFileRejectsUnsafePaths(t *testing.T) {
	for _, unsafe := range []string{"directory permissions", "record permissions", "lock permissions", "directory symlink", "record symlink", "lock symlink"} {
		t.Run(unsafe, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "cache")
			cache := NewFile(directory)
			store(t, cache, []byte("secret"))
			path := directory
			if strings.HasPrefix(unsafe, "record") {
				path = filepath.Join(directory, recordPrefix+testKey+".json")
			} else if strings.HasPrefix(unsafe, "lock") {
				path = filepath.Join(directory, lockName)
			}
			if strings.HasSuffix(unsafe, "permissions") {
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := cache.Update(t.Context(), testKey, func([]byte) ([]byte, error) {
				called = true
				return nil, nil
			})
			if err == nil || called {
				t.Fatalf("unsafe storage used: error=%v callback=%t", err, called)
			}
		})
	}
}

func TestFileSizeLimits(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	cache := NewFile(directory)
	store(t, cache, []byte("original"))
	path := filepath.Join(directory, recordPrefix+testKey+".json")
	oversized := bytes.Repeat([]byte("x"), maxFileSize+1)
	if err := cache.Update(t.Context(), testKey, func([]byte) ([]byte, error) { return oversized, nil }); err == nil {
		t.Fatal("oversized write succeeded")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "original" {
		t.Fatal("failed write replaced the stored record")
	}
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.Update(t.Context(), testKey, func(current []byte) ([]byte, error) {
		if current != nil {
			t.Fatal("oversized file was not treated as a cache miss")
		}
		return []byte("repaired"), nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFileRejectsInvalidKeys(t *testing.T) {
	for _, key := range []string{"", "../outside", strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		directory := filepath.Join(t.TempDir(), "cache")
		err := NewFile(directory).Update(t.Context(), key, func([]byte) ([]byte, error) {
			t.Fatal("invalid key reached callback")
			return nil, nil
		})
		if err == nil {
			t.Fatal("invalid cache key accepted")
		}
		if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid key performed filesystem I/O")
		}
	}
}

func ageCacheFile(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestFileCollectsOldRecordsDaily(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	cache := NewFile(directory)
	store(t, cache, []byte("current"))
	// Simulate successive OAuth tokens, each selecting a new opaque cache key.
	for i := range 32 {
		key := fmt.Sprintf("%064x", i)
		if err := cache.Update(t.Context(), key, func([]byte) ([]byte, error) {
			return []byte("old credential"), nil
		}); err != nil {
			t.Fatal(err)
		}
		ageCacheFile(t, filepath.Join(directory, recordPrefix+key+".json"))
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 34 {
		t.Fatalf("want 33 records and one lock, got %d entries: %v", len(entries), err)
	}
	lockPath := filepath.Join(directory, lockName)
	before, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh process/backend must honor the recent directory-wide GC time.
	store(t, NewFile(directory), []byte("current"))
	entries, err = os.ReadDir(directory)
	if err != nil || len(entries) != 34 {
		t.Fatalf("cleanup ran before the daily interval: %d entries, %v", len(entries), err)
	}
	ageCacheFile(t, lockPath)
	currentPath := filepath.Join(directory, recordPrefix+testKey+".json")
	ageCacheFile(t, currentPath)
	if err := NewFile(directory).Update(t.Context(), testKey, func(current []byte) ([]byte, error) {
		if string(current) != "current" {
			t.Fatalf("cleanup discarded the current transaction's record: %q", current)
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("want current record and one lock after GC, got %d entries: %v", len(entries), err)
	}
	after, err := os.Stat(lockPath)
	if err != nil || !os.SameFile(before, after) || time.Since(after.ModTime()) > time.Minute {
		t.Fatalf("cleanup replaced the lock inode or did not record its attempt: %v", err)
	}
	// Once due again, even that old record is collectible from another key.
	ageCacheFile(t, lockPath)
	if err := NewFile(directory).Update(t.Context(), fmt.Sprintf("%064x", 99), func([]byte) ([]byte, error) {
		return []byte("next"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(currentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old record survived the next daily cleanup: %v", err)
	}
}

func TestFileCleanupOnlyRemovesOwnedRegularFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	cache := NewFile(directory)
	store(t, cache, []byte("current"))
	oldRecord := recordPrefix + fmt.Sprintf("%064x", 1) + ".json"
	freshRecord := recordPrefix + fmt.Sprintf("%064x", 2) + ".json"
	legacyRecord := fmt.Sprintf("%064x", 3) + ".json"
	legacyLock := fmt.Sprintf("%064x", 3) + ".lock"
	oldTemp, freshTemp := tempPrefix+"old.tmp", tempPrefix+"fresh.tmp"
	for _, name := range []string{oldRecord, freshRecord, legacyRecord, legacyLock, oldTemp, freshTemp, "notes.json", "v2-invalid.json"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("opaque"), 0o600); err != nil {
			t.Fatal(err)
		}
		if name != freshRecord && name != freshTemp {
			ageCacheFile(t, path)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageCacheFile(t, outside)
	link := recordPrefix + fmt.Sprintf("%064x", 4) + ".json"
	if err := os.Symlink(outside, filepath.Join(directory, link)); err != nil {
		t.Fatal(err)
	}
	subdirectory := recordPrefix + fmt.Sprintf("%064x", 5) + ".json"
	if err := os.Mkdir(filepath.Join(directory, subdirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	ageCacheFile(t, filepath.Join(directory, subdirectory))
	ageCacheFile(t, filepath.Join(directory, lockName))
	store(t, cache, []byte("current"))
	for _, name := range []string{oldRecord, oldTemp} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("old cache file %s survived: %v", name, err)
		}
	}
	for _, name := range []string{freshRecord, freshTemp, legacyRecord, legacyLock, "notes.json", "v2-invalid.json", link, subdirectory, lockName} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err != nil {
			t.Errorf("cleanup removed %s: %v", name, err)
		}
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "keep" {
		t.Fatalf("cleanup followed a symlink: %q, %v", got, err)
	}
}

func TestFileCleanupProcessHelper(t *testing.T) {
	directory := os.Getenv("IQ_TEST_FILE_CACHE_DIRECTORY")
	if directory == "" {
		return
	}
	blocked := os.Getenv("IQ_TEST_FILE_CACHE_BLOCKED") == "1"
	timeout := 5 * time.Second
	if blocked {
		timeout = 100 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	called := false
	err := NewFile(directory).Update(ctx, fmt.Sprintf("%064x", 9), func([]byte) ([]byte, error) {
		called = true
		return []byte("other key"), nil
	})
	if blocked {
		if !errors.Is(err, context.DeadlineExceeded) || called {
			t.Fatalf("concurrent process bypassed the directory lock: error=%v, callback=%v", err, called)
		}
	} else if err != nil || !called {
		t.Fatalf("released directory lock not usable: error=%v, callback=%v", err, called)
	}
}

func TestFileCleanupWaitsForTransactionsAcrossProcesses(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "cache")
	cache := NewFile(directory)
	store(t, cache, []byte("before"))
	oldPath := filepath.Join(directory, recordPrefix+fmt.Sprintf("%064x", 1)+".json")
	if err := os.WriteFile(oldPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageCacheFile(t, oldPath)
	ageCacheFile(t, filepath.Join(directory, lockName))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(blocked string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, "-test.run=^TestFileCleanupProcessHelper$")
		command.Env = append(os.Environ(), "IQ_TEST_FILE_CACHE_DIRECTORY="+directory, "IQ_TEST_FILE_CACHE_BLOCKED="+blocked)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cache process: %v\n%s", err, output)
		}
	}
	if err := cache.Update(t.Context(), testKey, func([]byte) ([]byte, error) {
		// Another process, even for a different key, cannot run GC while
		// this callback might be refreshing credentials over the network.
		run("1")
		if _, err := os.Stat(oldPath); err != nil {
			t.Fatalf("cleanup ran during an active transaction: %v", err)
		}
		return []byte("after"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup did not run after the transaction: %v", err)
	}
	run("0")
}
