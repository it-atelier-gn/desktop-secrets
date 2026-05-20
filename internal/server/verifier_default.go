//go:build !hardened

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
