package onepassword

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	value   string
	expires time.Time
}

type Manager struct {
	mu    sync.Mutex
	cache map[string]cacheEntry
	ttl   time.Duration
	// runOp is injectable for tests.
	runOp func(ctx context.Context, args ...string) ([]byte, error)
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		cache: make(map[string]cacheEntry),
		ttl:   ttl,
		runOp: func(ctx context.Context, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, "op", args...)
			out, err := cmd.Output()
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return nil, fmt.Errorf("op: %s", strings.TrimSpace(string(ee.Stderr)))
				}
				return nil, fmt.Errorf("op: %w", err)
			}
			return out, nil
		},
	}
}

func (m *Manager) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

// ResolveSecret reads a value from 1Password via the `op` CLI.
// ref format: "VAULT/ITEM". field selects a named field on the item (1Password
// fields are native — no JSON parsing). If field is empty, the default
// `password` field is returned.
func (m *Manager) ResolveSecret(ctx context.Context, ref, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("empty op reference")
	}
	if !strings.Contains(ref, "/") {
		return "", errors.New("op: reference must be VAULT/ITEM")
	}
	if field == "" {
		field = "password"
	}

	opURI := "op://" + ref + "/" + field
	cacheKey := opURI
	if e, ok := m.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		return e.value, nil
	}

	out, err := m.runOp(ctx, "read", opURI)
	if err != nil {
		return "", fmt.Errorf("op: read %s: %w", opURI, err)
	}
	val := strings.TrimRight(string(out), "\r\n")

	m.cache[cacheKey] = cacheEntry{value: val, expires: time.Now().Add(m.ttl)}
	return val, nil
}
