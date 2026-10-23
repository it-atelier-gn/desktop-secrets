package memprotect

import "errors"

type Sealed struct {
	nonce []byte
	ct    []byte
	n     int
}

var errDestroyed = errors.New("memprotect: sealed value already destroyed")

func Seal(plaintext []byte) (*Sealed, error) {
	return seal(plaintext)
}

func SealString(s string) (*Sealed, error) {
	b := []byte(s)
	defer Wipe(b)
	return Seal(b)
}

func (s *Sealed) Open() ([]byte, error) {
	if s == nil || s.ct == nil {
		return nil, errDestroyed
	}
	return open(s)
}

func (s *Sealed) OpenString() (string, error) {
	pt, err := s.Open()
	if err != nil {
		return "", err
	}
	out := string(pt)
	Wipe(pt)
	return out, nil
}

func (s *Sealed) Destroy() {
	if s == nil {
		return
	}
	if s.ct != nil {
		Wipe(s.ct)
		s.ct = nil
	}
	if s.nonce != nil {
		Wipe(s.nonce)
		s.nonce = nil
	}
}

//go:noinline
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
