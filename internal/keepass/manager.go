package keepass

import (
	"context"
	"desktopsecrets/internal/prompt"
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
type keyfileMap map[string]string

type unlockedVault struct {
	db       *gokeepasslib.Database
	expires  time.Time
	mu       sync.RWMutex
	filename string
}

type KPManager struct {
	aliases   aliasMap
	keyfiles  keyfileMap
	vaults    map[string]*unlockedVault
	mu        sync.RWMutex
	unlockTTL *utils.AtomicDuration
}

func NewKPManager() *KPManager {
	return &KPManager{
		aliases:  make(aliasMap),
		keyfiles: make(keyfileMap),
		vaults:   make(map[string]*unlockedVault),
	}
}

func (m *KPManager) SetUnlockTTL(unlockTTL *utils.AtomicDuration) {
	m.unlockTTL = unlockTTL
}

func (m *KPManager) LoadAliases() error {
	settingsDir, err := utils.GetSettingsDirectory()
	if err != nil {
		return err
	}

	aliasesPath := filepath.Join(settingsDir, "aliases.yaml")

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

func (m *KPManager) LoadKeyfiles() error {
	settingsDir, err := utils.GetSettingsDirectory()
	if err != nil {
		return err
	}

	keyfilesPath := filepath.Join(settingsDir, "keyfiles.yaml")

	if keyfilesPathOverride := os.Getenv("DESKTOP_SECRETS_KEYFILES_FILE"); keyfilesPathOverride != "" {
		keyfilesPath = keyfilesPathOverride
	}

	if _, err := os.Stat(keyfilesPath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(keyfilesPath)
	if err != nil {
		return err
	}

	var kf map[string]string
	if err := yaml.Unmarshal(data, &kf); err != nil {
		return err
	}

	m.mu.Lock()
	m.keyfiles = kf
	m.mu.Unlock()
	return nil
}

func (m *KPManager) SaveKeyfiles() error {
	settingsDir, err := utils.GetSettingsDirectory()
	if err != nil {
		return err
	}

	keyfilesPath := filepath.Join(settingsDir, "keyfiles.yaml")

	if keyfilesPathOverride := os.Getenv("DESKTOP_SECRETS_KEYFILES_FILE"); keyfilesPathOverride != "" {
		keyfilesPath = keyfilesPathOverride
	}

	m.mu.RLock()
	data, err := yaml.Marshal(m.keyfiles)
	m.mu.RUnlock()
	if err != nil {
		return err
	}

	return os.WriteFile(keyfilesPath, data, 0600)
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

	// Get (or open) the unlocked vault. Prefer non-interactive unlock using nestedToken
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
	m.mu.Lock()
	if v, exists := m.vaults[key]; exists && v.db != nil && time.Now().Before(v.expires) {
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()

	// Try stored keyfile first
	m.mu.RLock()
	lastKeyfile := ""
	if m.keyfiles != nil {
		lastKeyfile = m.keyfiles[path]
	}
	m.mu.RUnlock()

	if lastKeyfile != "" {
		if u, err := m.openVaultWithKeyfile(path, lastKeyfile, ttl); err == nil {
			m.mu.Lock()
			m.vaults[key] = u
			m.mu.Unlock()
			return u, nil
		}
	}

	// Try non-interactive master password
	if master != "" {
		if u, err := m.openVaultWithMaster(path, master, ttl); err == nil {
			m.mu.Lock()
			m.vaults[key] = u
			m.mu.Unlock()
			return u, nil
		}
	}

	// Fall back to interactive prompt
	var err error
	var u *unlockedVault

	keepOpts := &prompt.KeepassOptions{
		KeepassFile: path,
		Keyfile:     lastKeyfile,
		UseKeyfile:  lastKeyfile != "",
		CurrentTTL:  int(m.unlockTTL.Load().Minutes()),
		Check: func(useKeyfile bool, keyfile string, password string, ttl int) error {
			if useKeyfile {
				u, err = m.openVaultWithKeyfile(path, keyfile, time.Duration(ttl)*time.Minute)
			} else {
				u, err = m.openVaultWithMaster(path, password, time.Duration(ttl)*time.Minute)
			}
			return err
		},
	}

	result, err := prompt.PromptForPassword("KeePass", prompt.StyleKeePass, keepOpts, nil)
	if err != nil {
		return nil, err
	}

	if result.Password == "" && !result.UseKeyfile {
		return nil, errors.New("empty master password")
	}

	if result.UseKeyfile {
		m.mu.Lock()
		if m.keyfiles == nil {
			m.keyfiles = make(map[string]string)
		}
		m.keyfiles[path] = result.Keyfile
		m.mu.Unlock()
		_ = m.SaveKeyfiles()
	}

	m.mu.Lock()
	m.vaults[key] = u
	m.mu.Unlock()

	return u, nil
}

func (m *KPManager) openVaultWithMaster(path, master string, ttl time.Duration) (*unlockedVault, error) {
	creds := gokeepasslib.NewPasswordCredentials(master)
	return m.openVault(path, ttl, creds)
}

func (m *KPManager) openVaultWithKeyfile(path, keyfile string, ttl time.Duration) (*unlockedVault, error) {
	info, err := os.Stat(keyfile)
	if err != nil {
		return nil, fmt.Errorf("stat keyfile: %w", err)
	}

	const maxPasswordSize = 4096

	if info.Size() > 0 && info.Size() <= maxPasswordSize {
		data, err := os.ReadFile(keyfile)
		if err != nil {
			return nil, fmt.Errorf("read keyfile: %w", err)
		}

		pwd := strings.TrimRight(string(data), "\r\n")

		if pwd != "" {
			if u, err := m.openVault(path, ttl, gokeepasslib.NewPasswordCredentials(pwd)); err == nil {
				return u, nil
			}
		}
	}

	creds, err := gokeepasslib.NewKeyCredentials(keyfile)
	if err != nil {
		return nil, fmt.Errorf("create key credentials: %w", err)
	}

	return m.openVault(path, ttl, creds)
}

func (m *KPManager) openVault(path string, ttl time.Duration, creds *gokeepasslib.DBCredentials) (*unlockedVault, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	db := gokeepasslib.NewDatabase()
	db.Credentials = creds

	dec := gokeepasslib.NewDecoder(f)
	if err := dec.Decode(db); err != nil {
		return nil, fmt.Errorf("decode kdbx: %w", err)
	}

	db.UnlockProtectedEntries()

	u := &unlockedVault{
		db:       db,
		expires:  time.Now().Add(ttl),
		filename: path,
	}

	// schedule expiry
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
