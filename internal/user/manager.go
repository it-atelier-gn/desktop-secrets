package user

import (
	"context"
	"desktopsecrets/internal/prompt"
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
	password  map[string]*passwordEntry
	mu        sync.RWMutex
	unlockTTL *utils.AtomicDuration
}

func NewUserManager() *UserManager {
	return &UserManager{
		password: make(map[string]*passwordEntry),
	}
}

func (m *UserManager) SetUnlockTTL(unlockTTL *utils.AtomicDuration) {
	m.unlockTTL = unlockTTL
}

func (m *UserManager) ResolvePassword(_ context.Context, title string, ttl time.Duration) (string, error) {
	m.mu.Lock()
	if v, exists := m.password[title]; exists && time.Now().Before(v.expires) {
		m.mu.Unlock()
		return v.password, nil
	}
	m.mu.Unlock()

	userOpts := &prompt.UserOptions{
		CurrentTTL: int(m.unlockTTL.Load().Minutes()),
		Prompt:     title,
	}

	result, err := prompt.PromptForPassword("User", prompt.StyleUser, nil, userOpts)
	if err != nil {
		return "", err
	}
	if result.Password == "" {
		return "", errors.New("empty password")
	}

	p := &passwordEntry{
		expires:  time.Now().Add(time.Duration(result.TTLMinutes) * time.Minute),
		password: result.Password,
	}

	m.mu.Lock()
	m.password[title] = p
	m.mu.Unlock()

	return p.password, nil
}
