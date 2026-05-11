package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// GetRuntimeDirectory returns a per-user 0700 directory for ephemeral
// state (sockets, lock files, shared-memory backing files).
//
// Resolution order:
//   - $DESKTOP_SECRETS_RUNTIME_DIR (test override)
//   - $XDG_RUNTIME_DIR/desktop-secrets        (Linux when set)
//   - %LOCALAPPDATA%\desktop-secrets\runtime  (Windows)
//   - $HOME/Library/Caches/desktop-secrets    (macOS)
//   - $HOME/.cache/desktop-secrets            (other Unix)
func GetRuntimeDirectory() (string, error) {
	if v := os.Getenv("DESKTOP_SECRETS_RUNTIME_DIR"); v != "" {
		if err := os.MkdirAll(v, 0o700); err != nil {
			return "", fmt.Errorf("create runtime directory %q: %w", v, err)
		}
		return v, nil
	}

	var dir string
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LocalAppData")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("locate runtime directory: %w", err)
			}
			base = filepath.Join(home, "AppData", "Local")
		}
		dir = filepath.Join(base, "desktop-secrets", "runtime")
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate runtime directory: %w", err)
		}
		dir = filepath.Join(home, "Library", "Caches", "desktop-secrets")
	default:
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			dir = filepath.Join(xdg, "desktop-secrets")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("locate runtime directory: %w", err)
			}
			dir = filepath.Join(home, ".cache", "desktop-secrets")
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create runtime directory %q: %w", dir, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dir, 0o700) // tighten if it pre-existed with looser perms
	}
	return dir, nil
}
