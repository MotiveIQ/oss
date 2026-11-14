package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/oauth2"
)

type credentials struct {
	Binding   string       `json:"binding"`
	IDToken   string       `json:"id_token"`
	Nonce     string       `json:"nonce"`
	Token     oauth2.Token `json:"oauth"`
	NoIDToken bool         `json:"no_id_token,omitempty"`
}

func privateFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("OIDC cache files must be regular files with permissions 0600")
	}
	return nil
}

func writeJSON(path string, value any) error {
	if err := privateFile(path); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".oidc-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(value)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}

func (s *oidcSource) update(ctx context.Context, update func(*credentials) (*credentials, error)) error {
	parent := filepath.Dir(s.path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("OIDC cache directory must have permissions 0700")
	}
	lockPath := s.path + ".lock"
	if err := privateFile(lockPath); err != nil {
		return err
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	defer lock.Close()
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("OIDC cache lock: %w", ctx.Err())
	}
	if err := privateFile(lockPath); err != nil {
		return err
	}
	if err := privateFile(s.path); err != nil {
		return err
	}
	var current *credentials
	file, err := os.Open(s.path)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if readErr != nil {
			return readErr
		}
		if len(data) > 1<<20 || json.Unmarshal(data, &current) != nil {
			return errors.New("invalid OIDC cache")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next, err := update(current)
	if err != nil || next == nil {
		return err
	}
	return writeJSON(s.path, next)
}
