package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
)

type cacheEntry struct {
	sealed  *memprotect.Sealed
	expires time.Time
}

type Manager struct {
	mu    sync.Mutex
	cfg   *aws.Config
	smCli *secretsmanager.Client
	psCli *ssm.Client
	cache map[string]cacheEntry
	ttl   time.Duration
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		cache: make(map[string]cacheEntry),
		ttl:   ttl,
	}
}

func (m *Manager) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

// init lazily loads AWS config and creates clients on first use.
func (m *Manager) init(ctx context.Context) error {
	if m.cfg != nil {
		return nil
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("AWS credentials not configured: %w", err)
	}
	m.cfg = &cfg
	m.smCli = secretsmanager.NewFromConfig(cfg)
	m.psCli = ssm.NewFromConfig(cfg)
	return nil
}

func (m *Manager) ResolveSecret(ctx context.Context, secretID, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.init(ctx); err != nil {
		return "", err
	}

	cacheKey := "sm:" + secretID
	if raw, ok := m.readCache(cacheKey); ok {
		return extractField(raw, field)
	}

	out, err := m.smCli.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return "", fmt.Errorf("awssm: failed to get secret %q: %w", secretID, err)
	}

	raw := ""
	if out.SecretString != nil {
		raw = *out.SecretString
	}

	m.storeCache(cacheKey, raw)
	return extractField(raw, field)
}

func (m *Manager) ResolveParameter(ctx context.Context, name, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.init(ctx); err != nil {
		return "", err
	}

	cacheKey := "ps:" + name
	if raw, ok := m.readCache(cacheKey); ok {
		return extractField(raw, field)
	}

	out, err := m.psCli.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("awsps: failed to get parameter %q: %w", name, err)
	}

	raw := ""
	if out.Parameter != nil && out.Parameter.Value != nil {
		raw = *out.Parameter.Value
	}

	m.storeCache(cacheKey, raw)
	return extractField(raw, field)
}

// readCache returns the decrypted plaintext for a cache key if present and
// not expired. Expired entries are evicted and zeroed.
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

// storeCache encrypts and inserts a new value, destroying any prior entry
// under the same key and scheduling a wipe at TTL expiry.
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

// extractField returns a JSON field from value if field is non-empty,
// otherwise returns the raw value.
func extractField(value, field string) (string, error) {
	if field == "" {
		return value, nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(value), &obj); err != nil {
		return "", fmt.Errorf("field %q requested but secret value is not valid JSON", field)
	}
	v, ok := obj[field]
	if !ok {
		return "", fmt.Errorf("field %q not found in secret", field)
	}
	switch s := v.(type) {
	case string:
		return s, nil
	default:
		return fmt.Sprintf("%v", s), nil
	}
}
