//go:build darwin

package keychain

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Manager struct{}

func NewManager() *Manager { return &Manager{} }

// Resolve looks up a generic password in the macOS login keychain.
// target is the service name; field is the account name (required).
// If field is empty the service alone is used (security will pick any matching account).
func (m *Manager) Resolve(ctx context.Context, service, account string) (string, error) {
	if strings.TrimSpace(service) == "" {
		return "", errors.New("keychain: empty service")
	}
	args := []string{"find-generic-password", "-s", service, "-w"}
	if strings.TrimSpace(account) != "" {
		args = append(args, "-a", account)
	}

	cmd := exec.CommandContext(ctx, "security", args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("keychain: %s/%s not found: %s", service, account, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("keychain: security: %w", err)
	}
	// security appends a trailing newline.
	return strings.TrimRight(string(out), "\r\n"), nil
}
