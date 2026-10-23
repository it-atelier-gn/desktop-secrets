//go:build !windows

package memprotect

import (
	"bytes"
	"testing"
)

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

func TestInitLocksKeyAndCipherState(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(keyPage) == 0 {
		t.Fatal("key page not mapped")
	}
}

func TestObjectBytesCoversWholeStruct(t *testing.T) {
	type state struct {
		a [40]byte
		b int64
	}
	v := &state{}
	v.b = 7
	b, err := objectBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 48 {
		t.Fatalf("len = %d, want 48", len(b))
	}
	wipeObject(v)
	if v.b != 0 {
		t.Fatal("wipeObject left data behind")
	}
	if _, err := objectBytes(state{}); err == nil {
		t.Fatal("non-pointer must be rejected")
	}
}
