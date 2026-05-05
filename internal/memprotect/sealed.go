package memprotect

import (
	"crypto/rand"
	"errors"
)

// Sealed holds an AES-GCM ciphertext of a secret. Plaintext only exists
// transiently while Open is called and must be wiped by the caller (or
// obtained via OpenString, which copies into an immutable string and wipes
// the intermediate buffer).
type Sealed struct {
	nonce []byte
	ct    []byte
}

// Seal encrypts plaintext under the process master key. The plaintext slice
// is NOT zeroed by this function — the caller decides whether the source
// buffer is safe to leak (e.g. after string conversion it is not).
func Seal(plaintext []byte) (*Sealed, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	s := &Sealed{nonce: nonce, ct: ct}
	_ = lockMemory(s.ct)
	return s, nil
}

// SealString encrypts a Go string. Note that the source string itself
// remains in memory until the runtime collects it; callers should avoid
// long-lived string copies of secrets.
func SealString(s string) (*Sealed, error) {
	return Seal([]byte(s))
}

// Open returns a freshly-allocated plaintext slice. The caller must Wipe it
// when done. Returns an error if Sealed was destroyed.
func (s *Sealed) Open() ([]byte, error) {
	if s == nil || s.ct == nil {
		return nil, errors.New("memprotect: sealed value already destroyed")
	}
	if err := ensureInit(); err != nil {
		return nil, err
	}
	return aead.Open(nil, s.nonce, s.ct, nil)
}

// OpenString decrypts and returns the plaintext as a string. The
// intermediate byte buffer is wiped before return. The returned string is
// itself unwipeable (Go strings are immutable) — keep its lifetime short.
func (s *Sealed) OpenString() (string, error) {
	pt, err := s.Open()
	if err != nil {
		return "", err
	}
	out := string(pt)
	Wipe(pt)
	return out, nil
}

// Destroy zeroes the ciphertext + nonce and unlocks the memory. Safe to
// call multiple times.
func (s *Sealed) Destroy() {
	if s == nil {
		return
	}
	if s.ct != nil {
		_ = unlockMemory(s.ct)
		Wipe(s.ct)
		s.ct = nil
	}
	if s.nonce != nil {
		Wipe(s.nonce)
		s.nonce = nil
	}
}

// Wipe overwrites b with zero bytes. The //go:noinline pragma prevents the
// compiler from eliding the writes when the slice goes out of scope at the
// call site.
//
//go:noinline
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
