//go:build !darwin

package keychain

import (
	"context"
	"errors"
)

type Manager struct{}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Resolve(_ context.Context, _, _ string) (string, error) {
	return "", errors.New("keychain is only supported on macOS")
}
