package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
)

type cacheEntry struct {
	sealed  *memprotect.Sealed
	expires time.Time
}

type logical interface {
	ReadWithContext(ctx context.Context, path string) (*vaultapi.Secret, error)
}

type Manager struct {
	mu        sync.Mutex
	cli       *vaultapi.Client
	logical   logical
	cache     map[string]cacheEntry
	ttl       time.Duration
	newClient func() (*vaultapi.Client, error)
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		cache: make(map[string]cacheEntry),
		ttl:   ttl,
		newClient: func() (*vaultapi.Client, error) {
			cfg := vaultapi.DefaultConfig()
			if err := cfg.Error; err != nil {
				return nil, err
			}
			return vaultapi.NewClient(cfg)
		},
	}
}

func (m *Manager) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

func (m *Manager) init() error {
	if m.logical != nil {
		return nil
	}
	c, err := m.newClient()
	if err != nil {
		return fmt.Errorf("Vault client not configured: %w", err)
	}
	m.cli = c
	m.logical = c.Logical()
	return nil
}

// ResolveSecret reads a secret at `path` from Vault. For KV v2 mounts, callers must
// include the `data/` segment in the path (e.g. `secret/data/myapp`). `field` selects
// a top-level key from the returned data map; for KV v2 the value is auto-unwrapped
// from the `data.data` payload.
func (m *Manager) ResolveSecret(ctx context.Context, path, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty vault path")
	}

	if raw, ok := m.readCache(path); ok {
		return selectField(raw, field)
	}

	if err := m.init(); err != nil {
		return "", err
	}

	sec, err := m.logical.ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault: read %q: %w", path, err)
	}
	if sec == nil {
		return "", fmt.Errorf("vault: path %q not found", path)
	}

	data := sec.Data
	// KV v2 responses wrap the actual secret under data.data
	if inner, ok := sec.Data["data"].(map[string]interface{}); ok {
		data = inner
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("vault: marshal response: %w", err)
	}

	m.storeCache(path, string(raw))
	return selectField(string(raw), field)
}

func (m *Manager) readCache(key string) (string, bool) {
	e, ok := m.cache[key]
	if !ok {
		return "", false
	}
	if !time.Now().Before(e.expires) {
		e.sealed.Destroy()
		delete(m.cache, key)
		return "", false
	}
	pt, err := e.sealed.OpenString()
	if err != nil {
		return "", false
	}
	return pt, true
}

func (m *Manager) storeCache(key, raw string) {
	sealed, err := memprotect.SealString(raw)
	if err != nil {
		return
	}
	if old, ok := m.cache[key]; ok {
		old.sealed.Destroy()
	}
	entry := cacheEntry{sealed: sealed, expires: time.Now().Add(m.ttl)}
	m.cache[key] = entry

	go func(k string, e cacheEntry, d time.Duration) {
		<-time.After(d)
		m.mu.Lock()
		if cur, ok := m.cache[k]; ok && cur.sealed == e.sealed {
			delete(m.cache, k)
		}
		m.mu.Unlock()
		e.sealed.Destroy()
	}(key, entry, m.ttl)
}

// selectField returns the requested field from a JSON-encoded map. If field is
// empty and the map has a single key, the value of that key is returned
// (matches the common KV convention where a secret has a `value` or `password`
// field). If multiple keys are present and no field is specified, the raw JSON
// is returned so callers can observe all fields.
func selectField(jsonMap, field string) (string, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonMap), &obj); err != nil {
		return "", fmt.Errorf("vault: response is not an object: %w", err)
	}
	if field == "" {
		if len(obj) == 1 {
			for _, v := range obj {
				return stringify(v), nil
			}
		}
		return jsonMap, nil
	}
	v, ok := obj[field]
	if !ok {
		return "", fmt.Errorf("vault: field %q not found", field)
	}
	return stringify(v), nil
}

func stringify(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprintf("%v", s)
	}
}
