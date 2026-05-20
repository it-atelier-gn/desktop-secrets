//go:build hardened && windows

package server

import (
	"fmt"
	"log"

	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

func ensureHardenedEnrollment() error {
	cred, err := osauth.LoadStoredCredential()
	if err != nil {
		log.Printf("osauth: stored credential load error: %v", err)
	}
	if cred != nil {
		return nil
	}
	if !osauth.WebAuthnAPIAvailable() {
		return fmt.Errorf("WebAuthn API not available on this system; hardened build requires Windows 10 1903+ with webauthn.dll")
	}
	log.Printf("hardened: no authenticator enrolled, starting enrollment")
	credID, pubKey, err := osauth.MakeWebAuthnCredential()
	if err != nil {
		return fmt.Errorf("authenticator enrollment failed: %w", err)
	}
	if err := osauth.SaveStoredCredential(osauth.StoredCredential{
		CredID: credID,
		PubKey: pubKey,
		Alg:    -7,
	}); err != nil {
		return fmt.Errorf("failed to persist authenticator credential: %w", err)
	}
	log.Printf("hardened: authenticator enrolled (%d byte credential)", len(credID))
	return nil
}
