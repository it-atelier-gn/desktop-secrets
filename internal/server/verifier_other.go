//go:build !windows

package server

import (
	"github.com/it-atelier-gn/desktop-secrets/internal/approval"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

func buildVerifier() approval.VerifierFunc {
	return func(reason string) (osauth.Factor, error) {
		return osauth.Verify(reason)
	}
}

func securityKeyAvailable() bool { return false }

func ensureSecurityKey() error { return osauth.ErrUnsupported }
