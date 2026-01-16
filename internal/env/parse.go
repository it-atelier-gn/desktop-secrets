package env

import (
	"bufio"
	"strings"
)

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
		val := parts[1]
		out[key] = val
	}
	return out
}
