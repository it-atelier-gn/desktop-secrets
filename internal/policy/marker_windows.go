//go:build windows

package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/dpapi"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

const markerFile = "hardened.marker"

type markerBlob struct {
	Version   int    `json:"version"`
	Hostname  string `json:"hostname"`
	Timestamp string `json:"timestamp"`
}

func markerPath() (string, error) {
	dir, err := utils.GetSettingsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, markerFile), nil
}

func MarkerExists() (bool, error) {
	p, err := markerPath()
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := dpapi.Unprotect(b); err != nil {
		return false, nil
	}
	return true, nil
}

func WriteMarker() error {
	p, err := markerPath()
	if err != nil {
		return err
	}
	if exists, err := MarkerExists(); err == nil && exists {
		return nil
	}
	host, _ := os.Hostname()
	plain, err := json.Marshal(markerBlob{
		Version:   1,
		Hostname:  host,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	cipher, err := dpapi.Protect(plain)
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

func DeleteMarker() error {
	p, err := markerPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
