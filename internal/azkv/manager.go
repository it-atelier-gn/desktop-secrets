package azkv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
)

// allowedVaultHostSuffixes pins the DNS suffixes the daemon will hand its
// AAD bearer token to. Azure Public + sovereign clouds + managed HSM.
var allowedVaultHostSuffixes = []string{
	".vault.azure.net",
	".vault.usgovcloudapi.net",
	".vault.azure.cn",
	".vault.microsoftazure.de",
	".managedhsm.azure.net",
	".managedhsm.usgovcloudapi.net",
	".managedhsm.azure.cn",
}

func isAllowedVaultHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Reject ports / userinfo — neither belongs in a vault host.
	if strings.ContainsAny(host, ":@") {
		return false
	}
	for _, suf := range allowedVaultHostSuffixes {
		if strings.HasSuffix(host, suf) && len(host) > len(suf) {
			label := host[:len(host)-len(suf)]
			if isValidDNSLabel(label) {
				return true
			}
		}
	}
	return false
}

func isValidDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

type cacheEntry struct {
	sealed  *memprotect.Sealed
	expires time.Time
}

type vaultClient interface {
	GetSecret(ctx context.Context, name, version string, opts *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

type Manager struct {
	mu      sync.Mutex
	cred    *azidentity.DefaultAzureCredential
	clients map[string]vaultClient
	cache   map[string]cacheEntry
	ttl     time.Duration
	// newClient is injectable for tests.
	newClient func(vaultURL string, cred *azidentity.DefaultAzureCredential) (vaultClient, error)
}

func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		clients: make(map[string]vaultClient),
		cache:   make(map[string]cacheEntry),
		ttl:     ttl,
		newClient: func(vaultURL string, cred *azidentity.DefaultAzureCredential) (vaultClient, error) {
			c, err := azsecrets.NewClient(vaultURL, cred, nil)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
}

func (m *Manager) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

func (m *Manager) ensureCred() error {
	if m.cred != nil {
		return nil
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("Azure credentials not configured: %w", err)
	}
	m.cred = cred
	return nil
}

func (m *Manager) clientFor(vault string) (vaultClient, error) {
	if c, ok := m.clients[vault]; ok {
		return c, nil
	}
	if err := m.ensureCred(); err != nil {
		return nil, err
	}
	url := vaultURL(vault)
	c, err := m.newClient(url, m.cred)
	if err != nil {
		return nil, fmt.Errorf("azkv: client for %q: %w", vault, err)
	}
	m.clients[vault] = c
	return c, nil
}

// ResolveSecret resolves an Azure Key Vault secret.
// ref format: "VAULT/NAME" — VAULT is the vault name (e.g. "mykv") or full URL.
func (m *Manager) ResolveSecret(ctx context.Context, ref, field string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	vault, name, err := splitVaultAndName(ref)
	if err != nil {
		return "", err
	}

	cacheKey := vault + "/" + name
	if raw, ok := m.readCache(cacheKey); ok {
		return extractField(raw, field)
	}

	cli, err := m.clientFor(vault)
	if err != nil {
		return "", err
	}

	resp, err := cli.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("azkv: get secret %q: %w", ref, err)
	}

	raw := ""
	if resp.Value != nil {
		raw = *resp.Value
	}

	m.storeCache(cacheKey, raw)
	return extractField(raw, field)
}

// Evict removes a single cache entry by key (vault + "/" + name).
func (m *Manager) Evict(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.cache[key]; ok {
		e.sealed.Destroy()
		delete(m.cache, key)
	}
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

// splitVaultAndName accepts either "VAULT/NAME" (VAULT a bare DNS label,
// normalised to https://VAULT.vault.azure.net) or "https://HOST/NAME" where
// HOST matches allowedVaultHostSuffixes. The allowlist is what stops an
// attacker-supplied URL from receiving the daemon's AAD bearer token.
func splitVaultAndName(s string) (vault, name string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty azkv reference")
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") {
		return "", "", fmt.Errorf("azkv: only https URLs are accepted")
	}
	if strings.HasPrefix(lower, "https://") {
		u, perr := url.Parse(s)
		if perr != nil || u.Host == "" {
			return "", "", fmt.Errorf("azkv: invalid URL")
		}
		if !isAllowedVaultHost(u.Host) {
			return "", "", fmt.Errorf("azkv: vault host %q is not an Azure Key Vault hostname", u.Host)
		}
		path := strings.Trim(u.Path, "/")
		if path == "" || strings.Contains(path, "/") {
			return "", "", fmt.Errorf("azkv: missing secret name after URL")
		}
		return "https://" + u.Host, path, nil
	}
	idx := strings.Index(s, "/")
	if idx < 0 {
		return "", "", fmt.Errorf("azkv: reference must be VAULT/NAME")
	}
	vault = strings.TrimSpace(s[:idx])
	name = strings.TrimSpace(s[idx+1:])
	if vault == "" || name == "" {
		return "", "", fmt.Errorf("azkv: VAULT and NAME must both be non-empty")
	}
	if !isValidDNSLabel(strings.ToLower(vault)) {
		return "", "", fmt.Errorf("azkv: VAULT %q is not a valid DNS label", vault)
	}
	return vault, name, nil
}

func vaultURL(vault string) string {
	if strings.HasPrefix(strings.ToLower(vault), "https://") {
		return vault
	}
	return "https://" + vault + ".vault.azure.net"
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
