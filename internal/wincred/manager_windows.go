//go:build windows

package wincred

import (
	"context"
	"fmt"
	"syscall"

	gowincred "github.com/danieljoos/wincred"
)

type Manager struct{}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Resolve(_ context.Context, target, field string) (string, error) {
	cred, err := gowincred.GetGenericCredential(target)
	if err != nil {
		return "", fmt.Errorf("credential %q not found: %w", target, err)
	}
	switch field {
	case "username":
		return cred.UserName, nil
	default: // "password" or empty
		return decodeBlob(cred.CredentialBlob), nil
	}
}

// decodeBlob decodes a credential blob.
// Windows tools (cmdkey, Credential Manager GUI) store passwords as UTF-16LE;
// fall back to raw UTF-8 string if decoding yields nothing.
func decodeBlob(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	if len(blob)%2 == 0 {
		u16 := make([]uint16, len(blob)/2)
		for i := range u16 {
			u16[i] = uint16(blob[2*i]) | uint16(blob[2*i+1])<<8
		}
		if s := syscall.UTF16ToString(u16); s != "" {
			return s
		}
	}
	return string(blob)
}
