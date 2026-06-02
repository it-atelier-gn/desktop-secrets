package keepass

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"

	"github.com/tobischo/gokeepasslib/v3"
	"gopkg.in/yaml.v3"
)

type alias struct {
	file   string
	master string
}

func (a *alias) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		a.file = s
		return nil
	}

	var aux struct {
		File   string `yaml:"file"`
		Master string `yaml:"master"`
	}
	if err := unmarshal(&aux); err == nil {
		a.file = aux.File
		a.master = aux.Master
		return nil
	}

	return fmt.Errorf("alias must be string or {file, master} object")
}

func (a alias) MarshalYAML() (any, error) {
	if a.master == "" {
		return a.file, nil
	}
	return struct {
		File   string `yaml:"file"`
		Master string `yaml:"master"`
	}{a.file, a.master}, nil
}

type aliasMap map[string]alias
type keyfileMap map[string]string

type AliasInfo struct {
	Name   string
	File   string
	Master string
}

type KeyfileInfo struct {
	Vault   string
	Keyfile string
}

type sealedEntry struct {
	pathSegs []string
	sealed   map[string]*memprotect.Sealed
	plain    map[string]string
}

type unlockedVault struct {
	entries  []*sealedEntry
	expires  time.Time
	mu       sync.RWMutex
	filename string
}

func (u *unlockedVault) destroy() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, e := range u.entries {
		for _, s := range e.sealed {
			s.Destroy()
		}
		e.sealed = nil
		e.plain = nil
	}
	u.entries = nil
	runtime.GC()
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

// IsVaultUnlocked reports whether a non-expired unlocked-vault cache
// entry exists for key. The resolver gate uses this to predict whether
// the next ResolvePassword call will trigger a master-password dialog
// — if it would, the separate retrieval-approval prompt is skipped and
// a successful unlock implicitly approves access.
func (m *KPManager) IsVaultUnlocked(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.vaults[key]
	return ok && v.entries != nil && time.Now().Before(v.expires)
}

// EvictVault drops the cached unlocked vault by its short key (alias
// or filepath.Base of the vault path). The vault must be re-unlocked
// on the next access. Used when the user picks Forget on the
// approval dialog.
func (m *KPManager) EvictVault(key string) {
	m.mu.Lock()
	v, ok := m.vaults[key]
	if ok {
		delete(m.vaults, key)
	}
	m.mu.Unlock()
	if v != nil {
		v.destroy()
	}
}

type CachedVault struct {
	Key      string
	Filename string
	Expires  time.Time
}

func (m *KPManager) CachedVaults() []CachedVault {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	out := make([]CachedVault, 0, len(m.vaults))
	for k, v := range m.vaults {
		if v.entries != nil && now.Before(v.expires) {
			out = append(out, CachedVault{Key: k, Filename: v.filename, Expires: v.expires})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (m *KPManager) EvictAll() {
	m.mu.Lock()
	vs := m.vaults
	m.vaults = make(map[string]*unlockedVault)
	m.mu.Unlock()
	for _, v := range vs {
		v.destroy()
	}
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

func aliasesFilePath() (string, error) {
	if override := os.Getenv("DESKTOP_SECRETS_ALIASES_FILE"); override != "" {
		return override, nil
	}
	dir, err := utils.GetSettingsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "aliases.yaml"), nil
}

func (m *KPManager) Aliases() []AliasInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AliasInfo, 0, len(m.aliases))
	for name, a := range m.aliases {
		out = append(out, AliasInfo{Name: name, File: a.file, Master: a.master})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *KPManager) SetAliases(list []AliasInfo) error {
	next := make(aliasMap, len(list))
	for _, ai := range list {
		name := strings.TrimSpace(ai.Name)
		file := strings.TrimSpace(ai.File)
		if name == "" || file == "" {
			return fmt.Errorf("alias name and file are required")
		}
		if _, dup := next[name]; dup {
			return fmt.Errorf("duplicate alias %q", name)
		}
		next[name] = alias{file: file, master: strings.TrimSpace(ai.Master)}
	}

	path, err := aliasesFilePath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(next)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	m.mu.Lock()
	m.aliases = next
	m.mu.Unlock()
	return nil
}

func (m *KPManager) Keyfiles() []KeyfileInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]KeyfileInfo, 0, len(m.keyfiles))
	for vault, kf := range m.keyfiles {
		out = append(out, KeyfileInfo{Vault: vault, Keyfile: kf})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Vault < out[j].Vault })
	return out
}

func (m *KPManager) SetKeyfiles(list []KeyfileInfo) error {
	next := make(keyfileMap, len(list))
	for _, ki := range list {
		vault := strings.TrimSpace(ki.Vault)
		kf := strings.TrimSpace(ki.Keyfile)
		if vault == "" || kf == "" {
			return fmt.Errorf("vault path and keyfile are required")
		}
		if _, dup := next[vault]; dup {
			return fmt.Errorf("duplicate vault %q", vault)
		}
		next[vault] = kf
	}

	m.mu.Lock()
	m.keyfiles = next
	m.mu.Unlock()
	return m.SaveKeyfiles()
}

func (m *KPManager) ResolvePassword(ctx context.Context, vault, entry string, master string, ttl time.Duration, resolve func(line string) (string, error)) (string, error) {
	var alias, dbPath string

	if after, ok := strings.CutPrefix(vault, "&"); ok {
		alias = after

		m.mu.RLock()
		al, ok := m.aliases[alias]
		m.mu.RUnlock()

		if !ok {
			return "", fmt.Errorf("alias %q not configured", alias)
		}

		dbPath = os.ExpandEnv(al.file)
		if al.master != "" {
			var err error
			if master, err = resolve(al.master); err != nil {
				return "", fmt.Errorf("failed to resolve master for alias %q", alias)
			}
		}
	} else {
		// Direct paths are NOT env-expanded: that would leak the daemon's
		// env back to the client via the error path. Use aliases for $VAR.
		dbPath = vault
		alias = filepath.Base(dbPath)
	}

	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	// Get (or open) the unlocked vault. Prefer non-interactive unlock using nestedToken
	vlt, err := m.getOrOpenVault(ctx, alias, abs, master, ttl)
	if err != nil {
		return "", err
	}

	entry, attr := splitAttribute(entry, "Password")

	vlt.mu.RLock()
	defer vlt.mu.RUnlock()
	if vlt.entries == nil {
		return "", errors.New("vault expired")
	}

	pwd, err := findAttribute(vlt.entries, entry, attr)
	if err != nil {
		return "", err
	}

	return pwd, nil
}

func (m *KPManager) getOrOpenVault(ctx context.Context, key, path, master string, ttl time.Duration) (*unlockedVault, error) {
	m.mu.Lock()
	if v, exists := m.vaults[key]; exists && v.entries != nil && time.Now().Before(v.expires) {
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
		if u, err := m.openVaultWithKeyfile(key, path, lastKeyfile, ttl); err == nil {
			m.mu.Lock()
			m.vaults[key] = u
			m.mu.Unlock()
			return u, nil
		}
	}

	// Try non-interactive master password
	if master != "" {
		if u, err := m.openVaultWithMaster(key, path, master, ttl); err == nil {
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
				u, err = m.openVaultWithKeyfile(key, path, keyfile, time.Duration(ttl)*time.Minute)
			} else {
				u, err = m.openVaultWithMaster(key, path, password, time.Duration(ttl)*time.Minute)
			}
			return err
		},
	}
	if info := clientinfo.InfoFromContext(ctx); info.PID != 0 || info.ExePath != "" || info.Name != "" {
		keepOpts.ProcessDisplay = info.EffectiveDisplay()
		keepOpts.ProcessDetails = info.EffectiveTooltip()
	}

	result, err := prompt.PromptForPassword("KeePass", prompt.StyleKeePass, keepOpts, nil)
	if err != nil {
		return nil, err
	}

	if result.Password == "" && !result.UseKeyfile {
		return nil, errors.New("empty master password")
	}
	result.Password = ""

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

func (m *KPManager) openVaultWithMaster(key, path, master string, ttl time.Duration) (*unlockedVault, error) {
	creds := gokeepasslib.NewPasswordCredentials(master)
	return m.openVault(key, path, ttl, creds)
}

func (m *KPManager) openVaultWithKeyfile(key, path, keyfile string, ttl time.Duration) (*unlockedVault, error) {
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
			if u, err := m.openVault(key, path, ttl, gokeepasslib.NewPasswordCredentials(pwd)); err == nil {
				return u, nil
			}
		}
	}

	creds, err := gokeepasslib.NewKeyCredentials(keyfile)
	if err != nil {
		return nil, fmt.Errorf("create key credentials: %w", err)
	}

	return m.openVault(key, path, ttl, creds)
}

func (m *KPManager) openVault(key, path string, ttl time.Duration, creds *gokeepasslib.DBCredentials) (*unlockedVault, error) {
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

	entries, err := sealProtectedEntries(db)
	if err != nil {
		return nil, fmt.Errorf("seal entries: %w", err)
	}

	db.Credentials = nil
	db.Content = nil
	db.Header = nil
	db = nil

	u := &unlockedVault{
		entries:  entries,
		expires:  time.Now().Add(ttl),
		filename: path,
	}

	runtime.GC()

	go func(key string, u *unlockedVault, ttl time.Duration) {
		<-time.After(ttl)
		m.mu.Lock()
		// Only delete if the cache still points at *this* vault — a
		// concurrent re-unlock would otherwise be evicted by us.
		if cur, ok := m.vaults[key]; ok && cur == u {
			delete(m.vaults, key)
		}
		m.mu.Unlock()
		u.destroy()
	}(key, u, ttl)

	return u, nil
}

func sealProtectedEntries(db *gokeepasslib.Database) ([]*sealedEntry, error) {
	var out []*sealedEntry
	if db == nil || db.Content == nil || db.Content.Root == nil {
		return out, nil
	}

	var walk func(g *gokeepasslib.Group, groupPath []string) error
	walk = func(g *gokeepasslib.Group, groupPath []string) error {
		curPath := groupPath
		if g.Name != "" {
			curPath = append(curPath, g.Name)
		}

		for ei := range g.Entries {
			e := &g.Entries[ei]
			title := ""
			for _, v := range e.Values {
				if v.Key == "Title" {
					title = v.Value.Content
					break
				}
			}
			if title == "" {
				continue
			}

			path := make([]string, len(curPath)+1)
			copy(path, curPath)
			path[len(curPath)] = title

			se := &sealedEntry{pathSegs: path}

			for vi := range e.Values {
				v := &e.Values[vi]
				if v.Value.Protected.Bool {
					s, err := memprotect.SealString(v.Value.Content)
					if err != nil {
						return err
					}
					if se.sealed == nil {
						se.sealed = make(map[string]*memprotect.Sealed)
					}
					se.sealed[v.Key] = s
					v.Value.Content = ""
				} else if v.Key != "Title" {
					if se.plain == nil {
						se.plain = make(map[string]string)
					}
					se.plain[v.Key] = v.Value.Content
				}
			}

			out = append(out, se)
		}

		for gi := range g.Groups {
			if err := walk(&g.Groups[gi], curPath); err != nil {
				return err
			}
		}
		return nil
	}

	for gi := range db.Content.Root.Groups {
		if err := walk(&db.Content.Root.Groups[gi], nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func splitAttribute(s, defaultAttr string) (before, after string) {
	if idx := strings.LastIndex(s, "|"); idx >= 0 {
		before = s[:idx]
		after = s[idx+1:]
		if after == "" {
			after = defaultAttr
		}
		return before, after
	}
	return s, "Password"
}

func findAttribute(entries []*sealedEntry, entry string, attributeName string) (string, error) {
	if entries == nil {
		return "", errors.New("database not unlocked")
	}

	if !strings.HasPrefix(entry, "/") {
		entry = "**/" + entry
	}

	patSegs, err := splitPattern(entry)
	if err != nil {
		return "", err
	}

	for _, se := range entries {
		if !matchSegments(patSegs, se.pathSegs) {
			continue
		}
		if s, ok := se.sealed[attributeName]; ok {
			return s.OpenString()
		}
		if v, ok := se.plain[attributeName]; ok {
			return v, nil
		}
		return "", nil
	}

	return "", fmt.Errorf("entry %q not found", entry)
}

// matchSeg is exponential in the number of "**" wildcards, and the pattern
// is client-controlled. Cap both to keep worst-case bounded.
const (
	maxPatternSegments = 64
	maxDoubleStars     = 4
)

// splitPattern splits a pattern like "/AWS/*/Prod/api-key" into segments,
// handling ** and escaped slashes (\/).

func splitPattern(p string) ([]string, error) {
	p = strings.TrimPrefix(p, "/")

	var segs []string
	var buf strings.Builder
	escaped := false

	for _, r := range p {
		switch {
		case escaped:
			// take character literally
			buf.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '/':
			segs = append(segs, buf.String())
			buf.Reset()
		default:
			buf.WriteRune(r)
		}
	}
	if escaped {
		return nil, fmt.Errorf("dangling escape in pattern %q", p)
	}
	if buf.Len() > 0 {
		segs = append(segs, buf.String())
	}

	if len(segs) > maxPatternSegments {
		return nil, fmt.Errorf("pattern has %d segments (max %d)", len(segs), maxPatternSegments)
	}
	doubleStars := 0
	for _, s := range segs {
		if s == "**" {
			doubleStars++
		}
	}
	if doubleStars > maxDoubleStars {
		return nil, fmt.Errorf("pattern has %d ** wildcards (max %d)", doubleStars, maxDoubleStars)
	}

	return segs, nil
}

// matchSegments matches pattern segments (with * and **) against a concrete path.
func matchSegments(pattern, path []string) bool {
	return matchSeg(pattern, path, 0, 0)
}

func matchSeg(pat, path []string, i, j int) bool {
	// If we've consumed the whole pattern, path must also be fully consumed.
	if i == len(pat) {
		return j == len(path)
	}

	// If this is a **, it can match zero or more segments.
	if pat[i] == "**" {
		// Try all possible consumptions of path[j:].
		for k := j; k <= len(path); k++ {
			if matchSeg(pat, path, i+1, k) {
				return true
			}
		}
		return false
	}

	// For anything else, we need at least one path segment left.
	if j == len(path) {
		return false
	}

	if pat[i] == "*" {
		// * matches exactly one segment
		return matchSeg(pat, path, i+1, j+1)
	}

	// Literal segment
	if pat[i] != path[j] {
		return false
	}
	return matchSeg(pat, path, i+1, j+1)
}
