package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/approval"
	"github.com/it-atelier-gn/desktop-secrets/internal/audit"
	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/env"
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
	if app.KP == nil || app.USER == nil || app.WINCRED == nil || app.AWS == nil ||
		app.AZKV == nil || app.GCPSM == nil || app.KEYCHAIN == nil ||
		app.VAULT == nil || app.ONEPASSWORD == nil {
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
		rawKey, rawVal, ok := strings.Cut(line, "=")
		if !ok {
			out = append(out, line)
			continue
		}
		key := strings.TrimSpace(rawKey)
		val := strings.TrimSpace(rawVal)

		if !env.IsValidKey(key) {
			errs = append(errs, fmt.Errorf("invalid environment variable name %q", key))
			continue
		}

		// Non-provider lines pass through verbatim. Server-side os.ExpandEnv
		// would expand against the daemon's env, leaking it to the client.
		lower := strings.ToLower(val)
		if !strings.HasPrefix(lower, "keepass(") && !strings.HasPrefix(lower, "user(") &&
			!strings.HasPrefix(lower, "wincred(") && !strings.HasPrefix(lower, "awssm(") &&
			!strings.HasPrefix(lower, "awsps(") && !strings.HasPrefix(lower, "azkv(") &&
			!strings.HasPrefix(lower, "gcpsm(") && !strings.HasPrefix(lower, "keychain(") &&
			!strings.HasPrefix(lower, "vault(") && !strings.HasPrefix(lower, "op(") {
			out = append(out, key+"="+val)
			continue
		}

		resolved, err := parseAndResolve(ctx, app, app.UnlockTTL.Load(), val)
		if err != nil {
			out = append(out, line) // keep original on error
			errs = append(errs, fmt.Errorf("key %s: %w", key, err))
			continue
		}
		out = append(out, key+"="+resolved)
	}

	return out, errs
}

// gate enforces retrieval-approval (when enabled). When approval is
// disabled or the gate field is nil (tests), it just calls fn.
//
// providerKey is the canonical lowercase ID stored in the approval
// store. providerRef is the human-readable form shown to the user.
// evictor is invoked when the user picks Forget.
func gate(ctx context.Context, app *AppState, providerKey, providerRef string, evictor approval.Evictor, fn func() (string, error)) (string, error) {
	return gateAutoApprove(ctx, app, providerKey, providerRef, evictor, nil, fn)
}

// gateAutoApprove is gate(...) with an extra "will-prompt" predicate.
// When approval is enabled and no live grant exists, the predicate
// reports whether fn() is itself going to put a password / unlock
// dialog in front of the user. If so, the separate retrieval-approval
// prompt is skipped — the user already has to consent to release the
// secret by entering the password — and a successful fn() implicitly
// records the grant. Subsequent calls (cache warm) fall back to the
// normal approval prompt, which is the point: approve once at unlock,
// then surface explicit approval prompts thereafter.
func gateAutoApprove(ctx context.Context, app *AppState, providerKey, providerRef string, evictor approval.Evictor, willPrompt func() bool, fn func() (string, error)) (string, error) {
	if app.Gate == nil || !app.RetrievalApproval.Load() {
		return fn()
	}
	pid := ClientPIDFromContext(ctx)
	info := clientinfo.InfoFromContext(ctx)
	if app.Gate.IsApproved(pid, providerKey) {
		app.Audit.LogDecision(info, audit.DecisionCached, providerKey, providerRef, "")
		return fn()
	}
	if app.AutoApproveOnUnlock.Load() && willPrompt != nil && willPrompt() {
		out, err := fn()
		if err != nil {
			app.Audit.LogDecision(info, audit.DecisionUnlockFailed, providerKey, providerRef, err.Error())
			return "", err
		}
		app.Gate.GrantImplicit(pid, providerKey)
		app.Audit.LogDecision(info, audit.DecisionAutoApproved, providerKey, providerRef, "")
		return out, nil
	}
	if err := app.Gate.Check(pid, providerKey, providerRef, evictor); err != nil {
		switch {
		case err == approval.ErrDenied:
			app.Audit.LogDecision(info, audit.DecisionDenied, providerKey, providerRef, "")
		case err == approval.ErrForgotten:
			app.Audit.LogDecision(info, audit.DecisionForgotten, providerKey, providerRef, "")
		default:
			app.Audit.LogDecision(info, audit.DecisionDenied, providerKey, providerRef, err.Error())
		}
		return "", err
	}
	app.Audit.LogDecision(info, audit.DecisionAllowed, providerKey, providerRef, "")
	return fn()
}

// parseAndResolve parses a top-level expression and resolves it.
// If a nested expression exists inside brackets, the nested expression is
// resolved first and its raw value is passed to the upper-level KP resolver
// via the context. No sanitization or mutation of the nested secret is performed.
func parseAndResolve(ctx context.Context, app *AppState, ttl time.Duration, s string) (string, error) {
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
		return gateAutoApprove(ctx, app, "user:"+title, fmt.Sprintf("user(%s)", title),
			func(_ string) { app.USER.Evict(title) },
			func() bool { return !app.USER.HasCached(title) },
			func() (string, error) {
				p, err := app.USER.ResolvePassword(ctx, title, ttl)
				if err != nil {
					return "", fmt.Errorf("user resolve failed: %w", err)
				}
				return p, nil
			})
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

		providerKey := "keepass:" + strings.ToLower(base) + "|" + title
		providerRef := fmt.Sprintf("keepass(%s | %s)", base, title)
		evictor := approval.Evictor(func(_ string) {
			// Drop the cached unlocked vault so the user has to
			// re-unlock on next access.
			app.KP.EvictVault(kpVaultKey(base))
		})

		// If there is a nested expression, resolve it first and pass it via context.
		if nestedExpr != "" {
			ne := strings.TrimSpace(nestedExpr)
			if !strings.HasPrefix(strings.ToLower(ne), "keepass(") && !strings.HasPrefix(strings.ToLower(ne), "user(") {
				return "", fmt.Errorf("nested expression must be keepass(...) or user(...): %q", ne)
			}
			nestedResolved, err := parseAndResolve(ctx, app, ttl, ne)
			if err != nil {
				return "", fmt.Errorf("resolving nested expression %q: %w", ne, err)
			}
			willPrompt := func() bool { return !app.KP.IsVaultUnlocked(kpVaultKey(base)) }
			return gateAutoApprove(ctx, app, providerKey, providerRef, evictor, willPrompt,
				func() (string, error) {
					p, err := app.KP.ResolvePassword(ctx, base, title, nestedResolved, ttl, func(expr string) (string, error) {
						return parseAndResolve(ctx, app, ttl, expr)
					})
					if err != nil {
						return "", fmt.Errorf("keepass resolve failed: %w", err)
					}
					return p, nil
				})
		}

		// no nested expression: call resolver normally
		willPrompt := func() bool { return !app.KP.IsVaultUnlocked(kpVaultKey(base)) }
		return gateAutoApprove(ctx, app, providerKey, providerRef, evictor, willPrompt,
			func() (string, error) {
				p, err := app.KP.ResolvePassword(ctx, base, title, "", ttl, func(expr string) (string, error) {
					return parseAndResolve(ctx, app, ttl, expr)
				})
				if err != nil {
					return "", fmt.Errorf("keepass resolve failed: %w", err)
				}
				return p, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "wincred(") {
		content, rem, err := parseParenContent(s[len("wincred"):])
		if err != nil {
			return "", fmt.Errorf("parse wincred: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after wincred expression")
		}
		content = strings.TrimSpace(content)
		if content == "" {
			return "", errors.New("empty wincred expression")
		}
		target, field := content, ""
		if idx := strings.LastIndex(content, "|"); idx >= 0 {
			target = strings.TrimSpace(content[:idx])
			field = strings.TrimSpace(content[idx+1:])
		}
		if target == "" {
			return "", errors.New("empty wincred target")
		}
		return gate(ctx, app, "wincred:"+target+"|"+field, fmt.Sprintf("wincred(%s|%s)", target, field), nil,
			func() (string, error) {
				v, err := app.WINCRED.Resolve(ctx, target, field)
				if err != nil {
					return "", fmt.Errorf("wincred resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "awssm(") {
		content, rem, err := parseParenContent(s[len("awssm"):])
		if err != nil {
			return "", fmt.Errorf("parse awssm: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after awssm expression")
		}
		secretID, field := splitFirstPipe(strings.TrimSpace(content))
		if secretID == "" {
			return "", errors.New("empty awssm secret id")
		}
		return gate(ctx, app, "awssm:"+secretID+"|"+field, fmt.Sprintf("awssm(%s|%s)", secretID, field),
			func(_ string) { app.AWS.Evict("sm:" + secretID) },
			func() (string, error) {
				v, err := app.AWS.ResolveSecret(ctx, secretID, field)
				if err != nil {
					return "", fmt.Errorf("awssm resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "awsps(") {
		content, rem, err := parseParenContent(s[len("awsps"):])
		if err != nil {
			return "", fmt.Errorf("parse awsps: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after awsps expression")
		}
		name, field := splitFirstPipe(strings.TrimSpace(content))
		if name == "" {
			return "", errors.New("empty awsps parameter name")
		}
		return gate(ctx, app, "awsps:"+name+"|"+field, fmt.Sprintf("awsps(%s|%s)", name, field),
			func(_ string) { app.AWS.Evict("ps:" + name) },
			func() (string, error) {
				v, err := app.AWS.ResolveParameter(ctx, name, field)
				if err != nil {
					return "", fmt.Errorf("awsps resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "azkv(") {
		content, rem, err := parseParenContent(s[len("azkv"):])
		if err != nil {
			return "", fmt.Errorf("parse azkv: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after azkv expression")
		}
		ref, field := splitFirstPipe(strings.TrimSpace(content))
		if ref == "" {
			return "", errors.New("empty azkv reference")
		}
		return gate(ctx, app, "azkv:"+ref+"|"+field, fmt.Sprintf("azkv(%s|%s)", ref, field),
			func(_ string) { app.AZKV.Evict(ref) },
			func() (string, error) {
				v, err := app.AZKV.ResolveSecret(ctx, ref, field)
				if err != nil {
					return "", fmt.Errorf("azkv resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "gcpsm(") {
		content, rem, err := parseParenContent(s[len("gcpsm"):])
		if err != nil {
			return "", fmt.Errorf("parse gcpsm: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after gcpsm expression")
		}
		ref, field := splitFirstPipe(strings.TrimSpace(content))
		if ref == "" {
			return "", errors.New("empty gcpsm reference")
		}
		return gate(ctx, app, "gcpsm:"+ref+"|"+field, fmt.Sprintf("gcpsm(%s|%s)", ref, field),
			func(_ string) { app.GCPSM.Evict(ref) },
			func() (string, error) {
				v, err := app.GCPSM.ResolveSecret(ctx, ref, field)
				if err != nil {
					return "", fmt.Errorf("gcpsm resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "keychain(") {
		content, rem, err := parseParenContent(s[len("keychain"):])
		if err != nil {
			return "", fmt.Errorf("parse keychain: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after keychain expression")
		}
		service, account := splitFirstPipe(strings.TrimSpace(content))
		if service == "" {
			return "", errors.New("empty keychain service")
		}
		return gate(ctx, app, "keychain:"+service+"|"+account, fmt.Sprintf("keychain(%s|%s)", service, account), nil,
			func() (string, error) {
				v, err := app.KEYCHAIN.Resolve(ctx, service, account)
				if err != nil {
					return "", fmt.Errorf("keychain resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "vault(") {
		content, rem, err := parseParenContent(s[len("vault"):])
		if err != nil {
			return "", fmt.Errorf("parse vault: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after vault expression")
		}
		path, field := splitFirstPipe(strings.TrimSpace(content))
		if path == "" {
			return "", errors.New("empty vault path")
		}
		return gate(ctx, app, "vault:"+path+"|"+field, fmt.Sprintf("vault(%s|%s)", path, field),
			func(_ string) { app.VAULT.Evict(path) },
			func() (string, error) {
				v, err := app.VAULT.ResolveSecret(ctx, path, field)
				if err != nil {
					return "", fmt.Errorf("vault resolve failed: %w", err)
				}
				return v, nil
			})
	}

	if strings.HasPrefix(strings.ToLower(s), "op(") {
		content, rem, err := parseParenContent(s[len("op"):])
		if err != nil {
			return "", fmt.Errorf("parse op: %w", err)
		}
		if strings.TrimSpace(rem) != "" {
			return "", fmt.Errorf("unexpected trailing characters after op expression")
		}
		ref, field := splitFirstPipe(strings.TrimSpace(content))
		if ref == "" {
			return "", errors.New("empty op reference")
		}
		return gate(ctx, app, "op:"+ref+"|"+field, fmt.Sprintf("op(%s|%s)", ref, field),
			func(_ string) { app.ONEPASSWORD.Evict(ref) },
			func() (string, error) {
				v, err := app.ONEPASSWORD.ResolveSecret(ctx, ref, field)
				if err != nil {
					return "", fmt.Errorf("op resolve failed: %w", err)
				}
				return v, nil
			})
	}

	return "", errors.New("not a recognized expression")
}

// kpVaultKey mirrors KPManager: aliases pass through, direct paths reduce
// to their basename. No env expansion (see keepass/manager.go).
func kpVaultKey(base string) string {
	if rest, ok := strings.CutPrefix(base, "&"); ok {
		return rest
	}
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		return base[i+1:]
	}
	return base
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

// splitFirstPipe splits s at the first '|', returning the part before and after.
// If no '|' is present, field is empty.
func splitFirstPipe(s string) (before, field string) {
	if a, b, ok := strings.Cut(s, "|"); ok {
		return strings.TrimSpace(a), strings.TrimSpace(b)
	}
	return s, ""
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
				switch vaultRaw[j] {
				case '[':
					depth++
				case ']':
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
