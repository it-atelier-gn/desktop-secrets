package policy

// Store is the OS-protected mirror of the policy block. Save encrypts
// the blob using a per-user key the user can't easily extract (DPAPI
// on Windows; Keychain / libsecret on macOS / Linux when those
// backends land). Load returns (nil, nil) when no policy has been
// stored yet — the caller treats that as first-run and adopts the
// disk policy without prompting.
type Store interface {
	Load() (*Policy, error)
	Save(p Policy) error
}
