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
)

type cacheEntry struct {
	value   string
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
	if e, ok := m.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		return extractField(e.value, field)
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

	m.cache[cacheKey] = cacheEntry{value: raw, expires: time.Now().Add(m.ttl)}
	return extractField(raw, field)
}

func (m *Manager) ResolveParameter(ctx context.Context, name, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.init(ctx); err != nil {
		return "", err
	}

	cacheKey := "ps:" + name
	if e, ok := m.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		return extractField(e.value, field)
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

	m.cache[cacheKey] = cacheEntry{value: raw, expires: time.Now().Add(m.ttl)}
	return extractField(raw, field)
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
