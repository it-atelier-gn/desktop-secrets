package user

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

type passwordEntry struct {
	expires time.Time
	sealed  *memprotect.Sealed
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

// HasCached reports whether a non-expired password is cached for title.
// Used by the resolver gate to decide whether the upcoming
// ResolvePassword call will trigger a UI prompt — if it would, the
// caller can skip the separate retrieval-approval dialog and treat the
// successful unlock as implicit approval.
func (m *UserManager) HasCached(title string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.password[title]
	return ok && time.Now().Before(v.expires)
}

// Evict removes a cached password by title.
func (m *UserManager) Evict(title string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.password[title]; ok {
		e.sealed.Destroy()
		delete(m.password, title)
	}
}

func (m *UserManager) ResolvePassword(ctx context.Context, title string, ttl time.Duration) (string, error) {
	m.mu.RLock()
	if v, exists := m.password[title]; exists && time.Now().Before(v.expires) {
		sealed := v.sealed
		m.mu.RUnlock()
		return sealed.OpenString()
	}
	m.mu.RUnlock()

	userOpts := &prompt.UserOptions{
		CurrentTTL: int(m.unlockTTL.Load().Minutes()),
		Prompt:     title,
	}
	if info := clientinfo.InfoFromContext(ctx); info.PID != 0 || info.ExePath != "" || info.Name != "" {
		userOpts.ClientDisplay = info.Short()
		userOpts.ClientDetails = info.Tooltip()
	}

	result, err := prompt.PromptForPassword("User", prompt.StyleUser, nil, userOpts)
	if err != nil {
		return "", err
	}
	if result.Password == "" {
		return "", errors.New("empty password")
	}

	sealed, err := memprotect.SealString(result.Password)
	if err != nil {
		return "", err
	}

	entryTTL := time.Duration(result.TTLMinutes) * time.Minute
	p := &passwordEntry{
		expires: time.Now().Add(entryTTL),
		sealed:  sealed,
	}

	m.mu.Lock()
	if old, ok := m.password[title]; ok {
		old.sealed.Destroy()
	}
	m.password[title] = p
	m.mu.Unlock()

	go func(title string, p *passwordEntry, d time.Duration) {
		<-time.After(d)
		m.mu.Lock()
		if cur, ok := m.password[title]; ok && cur == p {
			delete(m.password, title)
		}
		m.mu.Unlock()
		p.sealed.Destroy()
	}(title, p, entryTTL)

	return result.Password, nil
}
