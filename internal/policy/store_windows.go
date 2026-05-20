//go:build windows

package policy

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/it-atelier-gn/desktop-secrets/internal/dpapi"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

type winStore struct {
	path string
}

// DefaultStore returns the production keystore at
// <settings>/policy.dpapi. The directory is created lazily on first
// Save — Load handles the missing-file case as "first run".
func DefaultStore() (Store, error) {
	dir, err := utils.GetSettingsDirectory()
	if err != nil {
		return nil, err
	}
	return &winStore{path: filepath.Join(dir, "policy.dpapi")}, nil
}

func (s *winStore) Load() (*Policy, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := dpapi.Unprotect(b)
	if err != nil {
		return nil, nil
	}
	p, err := Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *winStore) Save(p Policy) error {
	plain, err := p.Marshal()
	if err != nil {
		return err
	}
	cipher, err := dpapi.Protect(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	_ = syscall.O_WRONLY
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, cipher, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
