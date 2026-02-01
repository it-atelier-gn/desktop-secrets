package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func GetSettingsDirectory() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", fmt.Errorf("failed to locate user config directory: %v; home dir lookup failed: %v", err, herr)
		}
		switch runtime.GOOS {
		case "windows":
			cfgDir = filepath.Join(home, "AppData", "Roaming")
		case "darwin":
			cfgDir = filepath.Join(home, "Library", "Application Support")
		default:
			cfgDir = filepath.Join(home, ".config")
		}
	}

	dir := filepath.Join(cfgDir, "desktop-secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create settings directory %q: %w", dir, err)
	}

	return dir, nil
}
