package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

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
