//go:build hardened && !windows

package server

import (
	"errors"

	"github.com/it-atelier-gn/desktop-secrets/internal/approval"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

func buildVerifier() approval.VerifierFunc {
	return func(reason string) (osauth.Factor, error) {
		return osauth.FactorClick, errors.New("hardened build is only supported on Windows")
	}
}
