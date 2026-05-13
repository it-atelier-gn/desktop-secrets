//go:build !windows

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

// On non-Windows platforms the keystore is currently a plain file in
// the settings directory. This is honest about being weaker than the
// Windows DPAPI path: any process running as the same user can read
// and write it. The TODO calls for libsecret on Linux and Keychain on
// macOS — slated for the platform-keyring work alongside polkit /
// LAContext factors.
type fileStore struct {
	path string
}

func DefaultStore() (Store, error) {
	dir, err := utils.GetSettingsDirectory()
	if err != nil {
		return nil, err
	}
	return &fileStore{path: filepath.Join(dir, "policy.json")}, nil
}

func (s *fileStore) Load() (*Policy, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *fileStore) Save(p Policy) error {
	b, err := p.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
