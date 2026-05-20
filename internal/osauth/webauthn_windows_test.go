//go:build windows

package osauth

import (
	"bytes"
	"testing"
)

func TestExtractCOSEFromAuthData(t *testing.T) {
	rpHash := bytes.Repeat([]byte{0xAA}, 32)
	flags := byte(0x41)
	signCount := []byte{0, 0, 0, 1}
	aaguid := bytes.Repeat([]byte{0xBB}, 16)
	credID := bytes.Repeat([]byte{0xCC}, 32)
	credIDLen := []byte{0, 32}
	cosePub := []byte{0xA5, 0x01, 0x02, 0x03, 0x26}

	var ad []byte
	ad = append(ad, rpHash...)
	ad = append(ad, flags)
	ad = append(ad, signCount...)
	ad = append(ad, aaguid...)
	ad = append(ad, credIDLen...)
	ad = append(ad, credID...)
	ad = append(ad, cosePub...)

	got, err := extractCOSEFromAuthData(ad)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, cosePub) {
		t.Fatalf("public key mismatch:\n got  %x\n want %x", got, cosePub)
	}
}

func TestExtractCOSE_NoAttestedFlag(t *testing.T) {
	ad := make([]byte, 40)
	ad[32] = 0x01
	_, err := extractCOSEFromAuthData(ad)
	if err == nil {
		t.Fatalf("expected error when AT flag is clear")
	}
}

func TestExtractCOSE_Truncated(t *testing.T) {
	ad := make([]byte, 30)
	_, err := extractCOSEFromAuthData(ad)
	if err == nil {
		t.Fatalf("expected error on short authData")
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	if c, err := LoadStoredCredential(); err != nil || c != nil {
		t.Fatalf("expected no credential initially, got %v err=%v", c, err)
	}

	in := StoredCredential{
		CredID: []byte{1, 2, 3, 4},
		PubKey: []byte{0xA5, 0x01, 0x02},
		Alg:    -7,
	}
	if err := SaveStoredCredential(in); err != nil {
		t.Fatalf("SaveStoredCredential: %v", err)
	}
	got, err := LoadStoredCredential()
	if err != nil {
		t.Fatalf("LoadStoredCredential: %v", err)
	}
	if got == nil {
		t.Fatalf("expected credential, got nil")
	}
	if !bytes.Equal(got.CredID, in.CredID) || !bytes.Equal(got.PubKey, in.PubKey) || got.Alg != in.Alg {
		t.Fatalf("round-trip mismatch: in=%+v out=%+v", in, *got)
	}
	if got.EnrolledAt == "" || got.Hostname == "" {
		t.Fatalf("expected EnrolledAt and Hostname to be populated, got %+v", *got)
	}

	if err := DeleteStoredCredential(); err != nil {
		t.Fatalf("DeleteStoredCredential: %v", err)
	}
	if c, err := LoadStoredCredential(); err != nil || c != nil {
		t.Fatalf("expected no credential after delete, got %v err=%v", c, err)
	}
}
