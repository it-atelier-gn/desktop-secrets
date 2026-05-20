//go:build windows

package osauth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/dpapi"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

const credFile = "webauthn.cred"

type StoredCredential struct {
	Version    int    `json:"version"`
	CredID     []byte `json:"cred_id"`
	PubKey     []byte `json:"pub_key"`
	Alg        int    `json:"alg"`
	EnrolledAt string `json:"enrolled_at"`
	Hostname   string `json:"hostname"`
}

func credPath() (string, error) {
	dir, err := utils.GetSettingsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, credFile), nil
}

func LoadStoredCredential() (*StoredCredential, error) {
	p, err := credPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := dpapi.Unprotect(b)
	if err != nil {
		return nil, nil
	}
	var c StoredCredential
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, err
	}
	if len(c.CredID) == 0 {
		return nil, nil
	}
	return &c, nil
}

func SaveStoredCredential(c StoredCredential) error {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.EnrolledAt == "" {
		c.EnrolledAt = time.Now().UTC().Format(time.RFC3339)
	}
	if c.Hostname == "" {
		host, _ := os.Hostname()
		c.Hostname = host
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	cipher, err := dpapi.Protect(plain)
	if err != nil {
		return err
	}
	p, err := credPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, cipher, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func DeleteStoredCredential() error {
	p, err := credPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
