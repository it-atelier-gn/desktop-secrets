package gcpsm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type cacheEntry struct {
	value   string
	expires time.Time
}

type smClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...any) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// concreteClient wraps *secretmanager.Client to satisfy smClient (variadic signature differs).
type concreteClient struct {
	c *secretmanager.Client
}

func (c *concreteClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...any) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return c.c.AccessSecretVersion(ctx, req)
}

func (c *concreteClient) Close() error { return c.c.Close() }

type Manager struct {
	mu        sync.Mutex
	cli       smClient
	cache     map[string]cacheEntry
	ttl       time.Duration
	newClient func(ctx context.Context) (smClient, error)
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		cache: make(map[string]cacheEntry),
		ttl:   ttl,
		newClient: func(ctx context.Context) (smClient, error) {
			c, err := secretmanager.NewClient(ctx)
			if err != nil {
				return nil, err
			}
			return &concreteClient{c: c}, nil
		},
	}
}

func (m *Manager) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

func (m *Manager) init(ctx context.Context) error {
	if m.cli != nil {
		return nil
	}
	c, err := m.newClient(ctx)
	if err != nil {
		return fmt.Errorf("GCP credentials not configured: %w", err)
	}
	m.cli = c
	return nil
}

// ResolveSecret resolves a GCP Secret Manager secret.
// ref format: "PROJECT/NAME" or "PROJECT/NAME/VERSION". Default version is "latest".
// Fully-qualified "projects/PROJECT/secrets/NAME/versions/VERSION" is also accepted.
func (m *Manager) ResolveSecret(ctx context.Context, ref, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	resource, err := buildResourceName(ref)
	if err != nil {
		return "", err
	}

	if e, ok := m.cache[resource]; ok && time.Now().Before(e.expires) {
		return extractField(e.value, field)
	}

	if err := m.init(ctx); err != nil {
		return "", err
	}

	resp, err := m.cli.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: resource})
	if err != nil {
		return "", fmt.Errorf("gcpsm: access %q: %w", resource, err)
	}

	raw := ""
	if resp.Payload != nil {
		raw = string(resp.Payload.Data)
	}

	m.cache[resource] = cacheEntry{value: raw, expires: time.Now().Add(m.ttl)}
	return extractField(raw, field)
}

// buildResourceName converts shorthand references into the fully-qualified
// "projects/P/secrets/N/versions/V" form expected by the API.
func buildResourceName(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("empty gcpsm reference")
	}
	if strings.HasPrefix(ref, "projects/") {
		return ref, nil
	}
	parts := strings.Split(ref, "/")
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("gcpsm: reference must be PROJECT/NAME[/VERSION]")
		}
		return fmt.Sprintf("projects/%s/secrets/%s/versions/latest", parts[0], parts[1]), nil
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return "", fmt.Errorf("gcpsm: reference must be PROJECT/NAME[/VERSION]")
		}
		return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", parts[0], parts[1], parts[2]), nil
	default:
		return "", fmt.Errorf("gcpsm: reference must be PROJECT/NAME[/VERSION]")
	}
}

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
