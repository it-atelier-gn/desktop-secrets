package user

import (
	"context"
	"desktopsecrets/internal/utils"
	"errors"
	"sync"
	"time"
)

type passwordEntry struct {
	expires  time.Time
	password string
}

type UserManager struct {
	password map[string]*passwordEntry
	mu       sync.RWMutex
}

func NewUserManager() *UserManager {
	return &UserManager{
		password: make(map[string]*passwordEntry),
	}
}

func (m *UserManager) ResolvePassword(_ context.Context, title string, ttl time.Duration) (string, error) {
	m.mu.Lock()
	if v, exists := m.password[title]; exists && time.Now().Before(v.expires) {
		m.mu.Unlock()
		return v.password, nil
	}
	m.mu.Unlock()

	password, err := utils.PromptForPassword(title)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("empty password")
	}

	p := &passwordEntry{
		expires:  time.Now().Add(ttl),
		password: password,
	}

	// Cache the unlocked vault.
	m.mu.Lock()
	m.password[title] = p
	m.mu.Unlock()

	return p.password, nil
}
