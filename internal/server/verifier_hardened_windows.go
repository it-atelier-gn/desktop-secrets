//go:build hardened && windows

package server

import (
	"errors"
	"log"

	"github.com/it-atelier-gn/desktop-secrets/internal/approval"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

func buildVerifier() approval.VerifierFunc {
	return func(reason string) (osauth.Factor, error) {
		cred, err := osauth.LoadStoredCredential()
		if err == nil && cred != nil {
			if err := osauth.VerifyWebAuthn(cred.CredID); err == nil {
				return osauth.FactorOSLocal, nil
			} else if errors.Is(err, osauth.ErrWebAuthnCanceled) {
				return osauth.FactorClick, osauth.ErrCanceled
			} else {
				log.Printf("osauth: WebAuthn verify failed: %v", err)
				return osauth.FactorClick, err
			}
		}
		return osauth.Verify(reason)
	}
}
