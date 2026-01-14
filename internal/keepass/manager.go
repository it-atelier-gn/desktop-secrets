package keepass

import (
	"context"
	"desktopsecrets/internal/utils"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	"gopkg.in/yaml.v3"
)

type aliasMap map[string]string

type unlockedVault struct {
	db       *gokeepasslib.Database
	expires  time.Time
	mu       sync.RWMutex
	filename string
}

type KPManager struct {
	aliases aliasMap
	vaults  map[string]*unlockedVault
	mu      sync.RWMutex
}

func NewKPManager() *KPManager {
	return &KPManager{
		aliases: make(aliasMap),
		vaults:  make(map[string]*unlockedVault),
	}
}

func (m *KPManager) LoadAliases() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	exeDir := filepath.Dir(exePath)
	aliasesPath := filepath.Join(exeDir, "aliases.yaml")

	if aliasesPathOverride := os.Getenv("DESKTOP_SECRETS_ALIASES_FILE"); aliasesPathOverride != "" {
		aliasesPath = aliasesPathOverride
	}

	if _, err := os.Stat(aliasesPath); os.IsNotExist(err) {
		return nil
	}

	aliasesBytes, err := os.ReadFile(aliasesPath)
	if err != nil {
		return err
	}

	var a aliasMap
	if err := yaml.Unmarshal(aliasesBytes, &a); err != nil {
		return err
	}

	for k, v := range a {
		a[k] = os.ExpandEnv(v)
	}

	m.mu.Lock()
	m.aliases = a
	m.mu.Unlock()
	return nil
}

func (m *KPManager) ResolvePassword(ctx context.Context, vault, title string, master string, ttl time.Duration) (string, error) {
	var alias, dbPath string

	if after, ok := strings.CutPrefix(vault, "&"); ok {
		alias = after
		m.mu.RLock()
		dbPath, ok = m.aliases[alias]
		m.mu.RUnlock()
		if !ok {
			return "", fmt.Errorf("alias %q not configured", alias)
		}
	} else {
		dbPath = os.ExpandEnv(vault)
		alias = filepath.Base(dbPath)
	}

	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	// Get (or open) the unlocked vault. Prefer non-interactive unlock using nestedToken.
	vlt, err := m.getOrOpenVault(alias, abs, master, ttl)
	if err != nil {
		return "", err
	}

	pwd, err := findPassword(vlt.db, title)
	if err != nil {
		return "", err
	}
	return pwd, nil
}

func (m *KPManager) getOrOpenVault(key, path, master string, ttl time.Duration) (*unlockedVault, error) {
	// Check cache.
	m.mu.Lock()
	if v, exists := m.vaults[key]; exists && v.db != nil && time.Now().Before(v.expires) {
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()

	// Try non-interactive unlock with provided token first.
	if master != "" {
		if u, err := m.openVaultWithMaster(path, master, ttl); err == nil {
			// cache and return
			m.mu.Lock()
			m.vaults[key] = u
			m.mu.Unlock()
			return u, nil
		} else {
			// Fail fast: do not prompt when a token was explicitly provided.
			return nil, fmt.Errorf("unlock with nested token failed: %w", err)
		}
	}

	// No token provided: fall back to interactive prompt (preserve existing behavior).
	master, err := utils.PromptForPassword(fmt.Sprintf("Unlock %s", key))
	if err != nil {
		return nil, err
	}
	if master == "" {
		return nil, errors.New("empty master password")
	}

	u, err := m.openVaultWithMaster(path, master, ttl)
	if err != nil {
		return nil, err
	}

	// Cache the unlocked vault.
	m.mu.Lock()
	m.vaults[key] = u
	m.mu.Unlock()

	return u, nil
}

// helper that opens, decodes, unlocks and schedules expiry; returns unlockedVault (but does not cache)
func (m *KPManager) openVaultWithMaster(path, master string, ttl time.Duration) (*unlockedVault, error) {
	// Open and decode with credentials set before decode.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(master)

	dec := gokeepasslib.NewDecoder(f)
	if err := dec.Decode(db); err != nil {
		return nil, fmt.Errorf("decode kdbx: %w", err)
	}

	// Unlock protected entries (no arguments).
	db.UnlockProtectedEntries()

	u := &unlockedVault{
		db:       db,
		expires:  time.Now().Add(ttl),
		filename: path,
	}

	// Schedule expiry to lock and clear from cache.
	go func(key string, u *unlockedVault, ttl time.Duration) {
		timer := time.NewTimer(ttl)
		<-timer.C
		u.mu.Lock()
		if u.db != nil {
			u.db.LockProtectedEntries()
			u.db = nil
		}
		u.mu.Unlock()
		m.mu.Lock()
		delete(m.vaults, key)
		m.mu.Unlock()
	}(filepath.Base(path), u, ttl)

	// Zero master variable as a best-effort hygiene step.
	master = ""

	return u, nil
}

func findPassword(db *gokeepasslib.Database, title string) (string, error) {
	if db == nil || db.Content.Root == nil {
		return "", errors.New("database not unlocked")
	}

	var walkGroup func(g gokeepasslib.Group) (string, bool)

	walkGroup = func(g gokeepasslib.Group) (string, bool) {
		for _, e := range g.Entries {
			var t string
			var p string
			for _, v := range e.Values {
				switch v.Key {
				case "Title":
					t = v.Value.Content
				case "Password":
					p = v.Value.Content
				}
			}
			if t == title {
				return p, true
			}
		}
		for _, sg := range g.Groups {
			if p, ok := walkGroup(sg); ok {
				return p, true
			}
		}
		return "", false
	}

	root := db.Content.Root
	for _, g := range root.Groups {
		if p, ok := walkGroup(g); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("entry %q not found", title)
}
