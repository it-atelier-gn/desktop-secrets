package env

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

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

var bracedVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandBraced(s string) string {
	return bracedVar.ReplaceAllStringFunc(s, func(m string) string { return os.Getenv(m[2 : len(m)-1]) })
}

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
		out.WriteString(expandBraced(val))
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
