package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ResolveEnvLines processes KEY=VALUE lines and replaces values of the form
// keepass(vault|title) and user(title) with resolved passwords. Bracketed vaults
// may contain at most one nested expression. When a nested expression is present,
// its resolved value is passed to the upper-level KP resolver via the context
// (not by mutating the vault string).
func ResolveEnvLines(ctx context.Context, app *AppState, lines []string) ([]string, []error) {
	var out []string
	var errs []error

	if app == nil {
		return lines, []error{errors.New("app state is nil")}
	}
	if app.KP == nil || app.USER == nil {
		return lines, []error{errors.New("resolvers not configured")}
	}

	for _, line := range lines {
		trim := strings.TrimSpace(line)
		// preserve comments and blank lines
		if trim == "" || strings.HasPrefix(trim, "#") {
			out = append(out, line)
			continue
		}

		// expect KEY=VALUE; if not present, leave unchanged
		idx := strings.Index(line, "=")
		if idx < 0 {
			out = append(out, line)
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		// only attempt parse when value clearly starts with keepass( or user(
		lower := strings.ToLower(val)
		if !strings.HasPrefix(lower, "keepass(") && !strings.HasPrefix(lower, "user(") {
			out = append(out, key+"="+os.ExpandEnv(val))
			continue
		}

		resolved, err := parseAndResolve(ctx, app.KP, app.USER, app.UnlockTTL.Load(), val)
		if err != nil {
			out = append(out, line) // keep original on error
			errs = append(errs, fmt.Errorf("key %s: %w", key, err))
			continue
		}
		out = append(out, key+"="+resolved)
	}

	return out, errs
}

// parseAndResolve parses a top-level expression and resolves it.
// If a nested expression exists inside brackets, the nested expression is
// resolved first and its raw value is passed to the upper-level KP resolver
// via the context. No sanitization or mutation of the nested secret is performed.
func parseAndResolve(ctx context.Context, kp KPResolver, user UserResolver, ttl time.Duration, s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(s), "user(") {
		title, rem, err := parseParenContent(s[len("user"):])
		if err != nil {
			return "", fmt.Errorf("parse user: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after user expression")
		}
		title = strings.TrimSpace(title)
		if title == "" {
			return "", errors.New("empty user title")
		}
		pass, err := user.ResolvePassword(ctx, title, ttl)
		if err != nil {
			return "", fmt.Errorf("user resolve failed: %w", err)
		}
		return pass, nil
	}

	if strings.HasPrefix(strings.ToLower(s), "keepass(") {
		content, rem, err := parseParenContent(s[len("keepass"):])
		if err != nil {
			return "", fmt.Errorf("parse keepass: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after keepass expression")
		}
		sepIdx := indexTopLevelPipe(content)
		if sepIdx < 0 {
			return "", errors.New("missing '|' separator in keepass expression")
		}
		vaultRaw := strings.TrimSpace(content[:sepIdx])
		title := strings.TrimSpace(content[sepIdx+1:])
		if title == "" {
			return "", errors.New("empty keepass title")
		}

		// Simplified chaining: allow at most one nested expression inside brackets.
		base, nestedExpr, err := splitVaultAndSingleNested(vaultRaw)
		if err != nil {
			return "", fmt.Errorf("invalid vault expression: %w", err)
		}

		// If there is a nested expression, resolve it first and pass it via context.
		if nestedExpr != "" {
			ne := strings.TrimSpace(nestedExpr)
			if !strings.HasPrefix(strings.ToLower(ne), "keepass(") && !strings.HasPrefix(strings.ToLower(ne), "user(") {
				return "", fmt.Errorf("nested expression must be keepass(...) or user(...): %q", ne)
			}
			nestedResolved, err := parseAndResolve(ctx, kp, user, ttl, ne)
			if err != nil {
				return "", fmt.Errorf("resolving nested expression %q: %w", ne, err)
			}
			// pass nestedResolved via context to the upper-level KP resolver
			pass, err := kp.ResolvePassword(ctx, base, title, nestedResolved, ttl)
			if err != nil {
				return "", fmt.Errorf("keepass resolve failed: %w", err)
			}
			return pass, nil
		}

		// no nested expression: call resolver normally
		pass, err := kp.ResolvePassword(ctx, base, title, "", ttl)
		if err != nil {
			return "", fmt.Errorf("keepass resolve failed: %w", err)
		}
		return pass, nil
	}

	return "", errors.New("not a recognized expression")
}

// parseParenContent returns the content inside the first matching top-level parentheses
// and the remainder after the closing ')'.
func parseParenContent(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s[0] != '(' {
		return "", "", errors.New("expected '('")
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '(' {
			depth++
			continue
		}
		if ch == ')' {
			depth--
			if depth == 0 {
				return s[1:i], s[i+1:], nil
			}
		}
	}
	return "", "", errors.New("unclosed '('")
}

// indexTopLevelPipe finds the index of '|' that is at top-level (not inside parentheses or brackets).
func indexTopLevelPipe(s string) int {
	depthPar := 0
	depthBr := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '(':
			depthPar++
		case ')':
			if depthPar > 0 {
				depthPar--
			}
		case '[':
			depthBr++
		case ']':
			if depthBr > 0 {
				depthBr--
			}
		case '|':
			if depthPar == 0 && depthBr == 0 {
				return i
			}
		}
	}
	return -1
}

// splitVaultAndSingleNested extracts base and at most one nested expression inside brackets.
// If no brackets are present, nestedExpr is empty.
func splitVaultAndSingleNested(vaultRaw string) (base string, nestedExpr string, err error) {
	vaultRaw = strings.TrimSpace(vaultRaw)
	if vaultRaw == "" {
		return "", "", errors.New("empty vault")
	}
	// find first '[' at top level
	for i := 0; i < len(vaultRaw); i++ {
		if vaultRaw[i] == '[' {
			// find matching top-level ']'
			depth := 0
			for j := i; j < len(vaultRaw); j++ {
				if vaultRaw[j] == '[' {
					depth++
				} else if vaultRaw[j] == ']' {
					depth--
					if depth == 0 {
						base = strings.TrimSpace(vaultRaw[:i])
						content := strings.TrimSpace(vaultRaw[i+1 : j])
						// simplified: do not allow commas; only a single nested expression allowed
						if strings.Contains(content, ",") {
							return "", "", errors.New("multiple nested items not allowed in simplified chaining")
						}
						return base, content, nil
					}
				}
			}
			return "", "", errors.New("unclosed '[' in vault")
		}
	}
	// no brackets
	return vaultRaw, "", nil
}
