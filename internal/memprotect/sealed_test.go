package memprotect

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	pt := []byte("hunter2-very-secret")
	s, err := Seal(pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := s.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, pt)
	}
}

func TestSealStringOpenString(t *testing.T) {
	const want = "p@ssw0rd"
	s, err := SealString(want)
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	got, err := s.OpenString()
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCiphertextDiffersFromPlaintext(t *testing.T) {
	pt := []byte("the-secret-value")
	s, err := Seal(pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(s.ct, pt) {
		t.Fatalf("ciphertext contains plaintext bytes")
	}
}

func TestNoncesAreUnique(t *testing.T) {
	pt := []byte("same-input")
	a, _ := Seal(pt)
	b, _ := Seal(pt)
	if bytes.Equal(a.nonce, b.nonce) {
		t.Fatalf("nonces collided")
	}
	if bytes.Equal(a.ct, b.ct) {
		t.Fatalf("ciphertexts identical for same plaintext (nonce reuse)")
	}
}

func TestDestroyZeroesAndPreventsOpen(t *testing.T) {
	s, err := Seal([]byte("destroy-me"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	s.Destroy()
	if _, err := s.Open(); err == nil {
		t.Fatalf("Open after Destroy should fail")
	}
	// Double-destroy must not panic.
	s.Destroy()
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}

func TestEmptyPlaintext(t *testing.T) {
	s, err := Seal(nil)
	if err != nil {
		t.Fatalf("Seal(nil): %v", err)
	}
	got, err := s.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}
