//go:build windows

package server

import (
	"errors"
	"fmt"
	"log"

	"github.com/it-atelier-gn/desktop-secrets/internal/approval"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

func buildVerifier() approval.VerifierFunc {
	return func(reason string) (osauth.Factor, error) {
		cred, err := osauth.LoadStoredCredential()
		if err != nil {
			log.Printf("osauth: stored credential load error: %v", err)
		}
		if cred == nil && !osauth.Available() && osauth.WebAuthnAPIAvailable() {
			if cred, err = enrollSecurityKey(); err != nil {
				log.Printf("osauth: %v", err)
				return osauth.FactorClick, err
			}
		}
		if cred != nil {
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

func securityKeyAvailable() bool {
	return osauth.WebAuthnAPIAvailable()
}

func ensureSecurityKey() error {
	if cred, _ := osauth.LoadStoredCredential(); cred != nil {
		return nil
	}
	_, err := enrollSecurityKey()
	return err
}

func enrollSecurityKey() (*osauth.StoredCredential, error) {
	log.Printf("osauth: no authenticator enrolled, starting enrollment")
	credID, pubKey, err := osauth.MakeWebAuthnCredential()
	if err != nil {
		return nil, fmt.Errorf("authenticator enrollment failed: %w", err)
	}
	cred := osauth.StoredCredential{CredID: credID, PubKey: pubKey, Alg: -7}
	if err := osauth.SaveStoredCredential(cred); err != nil {
		return nil, fmt.Errorf("failed to persist authenticator credential: %w", err)
	}
	log.Printf("osauth: authenticator enrolled (%d byte credential)", len(credID))
	return &cred, nil
}
