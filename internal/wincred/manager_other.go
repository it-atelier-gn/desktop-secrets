//go:build !windows

package wincred

import (
	"context"
	"errors"
)

type Manager struct{}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Resolve(_ context.Context, target, field string) (string, error) {
	return "", errors.New("wincred is only supported on Windows")
}
