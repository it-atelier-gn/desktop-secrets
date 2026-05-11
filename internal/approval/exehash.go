package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// computeExeHash returns the lowercase hex SHA-256 of the file at path.
// Best-effort: any error (file gone, permission denied, etc.) returns
// "" so the caller can decide how to interpret an unknown fingerprint.
func computeExeHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// exeHashMatches returns true when:
//   - the grant carries no fingerprint (legacy / capture failed at grant time), or
//   - the binary at path still hashes to want.
//
// Returns false when the recorded hash is non-empty and the current
// file's hash differs or cannot be read — i.e. a replaced or missing
// binary fails the pin and the grant is treated as expired.
func exeHashMatches(path, want string) bool {
	if want == "" {
		return true
	}
	got, err := computeExeHash(path)
	if err != nil {
		return false
	}
	return got == want
}
