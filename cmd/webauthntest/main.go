//go:build windows

// webauthntest walks the Win32 WebAuthn API (webauthn.dll) end-to-end:
// it registers a fresh cross-platform credential (so it skips the
// platform authenticator and goes straight to a security key like
// YubiKey), then asserts against that credential. Each call prints its
// HRESULT and the relevant bytes.
//
// Build: go build -o webauthntest.exe ./cmd/webauthntest
// Run:   .\webauthntest.exe
//
// The test does not persist anything. It exists to confirm that the
// WebAuthn API and a connected security key cooperate before the real
// factor is wired into the daemon.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// webauthn.h constants (subset).
const (
	rpEntityInfoCurrentVersion       = 1
	userEntityInfoCurrentVersion     = 1
	clientDataCurrentVersion         = 1
	coseCredParamCurrentVersion      = 1
	credentialCurrentVersion         = 1
	makeCredOptionsVersion1          = 1
	getAssertionOptionsVersion1      = 1

	attachmentAny            = 0
	attachmentPlatform       = 1
	attachmentCrossPlatform  = 2

	uvRequirementAny         = 0
	uvRequirementRequired    = 1
	uvRequirementPreferred   = 2
	uvRequirementDiscouraged = 3

	attestationNone = 1

	coseAlgES256 = -7

	timeoutMs = 60_000
)

var (
	credTypePublicKey = mustUTF16Ptr("public-key")
	hashAlgSHA256     = mustUTF16Ptr("SHA-256")

	rpID   = mustUTF16Ptr("desktop-secrets.local")
	rpName = mustUTF16Ptr("Desktop Secrets")

	userName        = mustUTF16Ptr("desktop-secrets")
	userDisplayName = mustUTF16Ptr("Desktop Secrets")
)

func mustUTF16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

// --- struct layouts (match webauthn.h byte-for-byte) ---

type rpEntityInfo struct {
	Version uint32
	ID      *uint16
	Name    *uint16
	Icon    *uint16
}

type userEntityInfo struct {
	Version     uint32
	CbID        uint32
	PbID        *byte
	Name        *uint16
	Icon        *uint16
	DisplayName *uint16
}

type coseCredParam struct {
	Version        uint32
	CredentialType *uint16
	Alg            int32
}

type coseCredParams struct {
	Count  uint32
	Params *coseCredParam
}

type clientData struct {
	Version          uint32
	CbClientDataJSON uint32
	PbClientDataJSON *byte
	HashAlgID        *uint16
}

type credential struct {
	Version        uint32
	CbID           uint32
	PbID           *byte
	CredentialType *uint16
}

type credentials struct {
	Count       uint32
	Credentials *credential
}

type extensions struct {
	Count      uint32
	Extensions uintptr
}

type makeCredOptions struct {
	Version                  uint32
	TimeoutMS                uint32
	ExcludeList              credentials
	Extensions               extensions
	AuthenticatorAttachment  uint32
	RequireResidentKey       uint32 // BOOL
	UserVerificationReq      uint32
	AttestationConveyance    uint32
	Flags                    uint32
}

type getAssertionOptions struct {
	Version                 uint32
	TimeoutMS               uint32
	AllowList               credentials
	Extensions              extensions
	AuthenticatorAttachment uint32
	UserVerificationReq     uint32
	Flags                   uint32
}

// Output structs. We only read fields up to and including CredentialId
// for MakeCredential. The full struct in webauthn.h is bigger but the
// trailing fields are version-gated — reading past CbCredentialId on a
// V1 surface is safe because the API allocates the full block.
type credentialAttestation struct {
	Version                 uint32
	FormatType              *uint16
	CbAuthenticatorData     uint32
	PbAuthenticatorData     *byte
	CbAttestation           uint32
	PbAttestation           *byte
	AttestationDecodeType   uint32
	PvAttestationDecode     uintptr
	CbAttestationObject     uint32
	PbAttestationObject     *byte
	CbCredentialID          uint32
	PbCredentialID          *byte
}

type assertion struct {
	Version             uint32
	CbAuthenticatorData uint32
	PbAuthenticatorData *byte
	CbSignature         uint32
	PbSignature         *byte
	Credential          credential
	CbUserID            uint32
	PbUserID            *byte
}

// --- DLL bindings ---

var (
	modWebAuthn = windows.NewLazySystemDLL("webauthn.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetAPIVersionNumber   = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procIsUVPAA               = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procMakeCredential        = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procFreeAttestation       = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procGetAssertion          = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeAssertion         = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procGetErrorName          = modWebAuthn.NewProc("WebAuthNGetErrorName")

	procGetConsoleWindow = modKernel32.NewProc("GetConsoleWindow")
)

func hrName(hr uintptr) string {
	if procGetErrorName.Find() != nil {
		return ""
	}
	r, _, _ := procGetErrorName.Call(hr)
	if r == 0 {
		return ""
	}
	// Returned pointer is a static PCWSTR owned by webauthn.dll — do
	// not free.
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(r)))
}

func consoleHWND() uintptr {
	h, _, _ := procGetConsoleWindow.Call()
	return h
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func bytePtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

// clientDataBytes returns a minimal CollectedClientData JSON blob. We
// don't base64url-encode the challenge here — the API only hashes the
// bytes we hand it, and what's hashed has to match what the
// authenticator signs. For the test, opaque bytes are fine.
func clientDataBytes(op, challenge string) []byte {
	return []byte(fmt.Sprintf(
		`{"type":"webauthn.%s","challenge":%q,"origin":"https://desktop-secrets.local","crossOrigin":false}`,
		op, challenge,
	))
}

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fmt.Println("=== WebAuthn probe ===")

	v, _, _ := procGetAPIVersionNumber.Call()
	fmt.Printf("WebAuthNGetApiVersionNumber = %d\n", v)

	var uvpaa int32
	hr, _, _ := procIsUVPAA.Call(uintptr(unsafe.Pointer(&uvpaa)))
	fmt.Printf("UserVerifyingPlatformAuthenticatorAvailable: HRESULT=0x%08x value=%v\n",
		uint32(hr), uvpaa != 0)

	hwnd := consoleHWND()
	fmt.Printf("Parent HWND (console) = 0x%x\n", hwnd)

	// --- Step 1: MakeCredential against a cross-platform authenticator (security key) ---
	fmt.Println("\n-- Step 1: WebAuthNAuthenticatorMakeCredential (tap your security key)")

	userID := random(32)
	challenge := random(32)
	cdBytes := clientDataBytes("create", hex.EncodeToString(challenge))

	rp := rpEntityInfo{
		Version: rpEntityInfoCurrentVersion,
		ID:      rpID,
		Name:    rpName,
	}
	user := userEntityInfo{
		Version:     userEntityInfoCurrentVersion,
		CbID:        uint32(len(userID)),
		PbID:        bytePtr(userID),
		Name:        userName,
		DisplayName: userDisplayName,
	}
	cd := clientData{
		Version:          clientDataCurrentVersion,
		CbClientDataJSON: uint32(len(cdBytes)),
		PbClientDataJSON: bytePtr(cdBytes),
		HashAlgID:        hashAlgSHA256,
	}
	param := coseCredParam{
		Version:        coseCredParamCurrentVersion,
		CredentialType: credTypePublicKey,
		Alg:            coseAlgES256,
	}
	params := coseCredParams{
		Count:  1,
		Params: &param,
	}
	opts := makeCredOptions{
		Version:                 makeCredOptionsVersion1,
		TimeoutMS:               timeoutMs,
		AuthenticatorAttachment: attachmentCrossPlatform,
		RequireResidentKey:      0,
		UserVerificationReq:     uvRequirementRequired,
		AttestationConveyance:   attestationNone,
	}

	var att *credentialAttestation
	start := time.Now()
	hr, _, _ = procMakeCredential.Call(
		hwnd,
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&att)),
	)
	elapsed := time.Since(start)
	fmt.Printf("   HRESULT=0x%08x  (%s)  elapsed=%s\n", uint32(hr), hrName(hr), elapsed)
	if hr != 0 || att == nil {
		fmt.Println("   ABORT: MakeCredential failed.")
		return
	}
	credID := make([]byte, att.CbCredentialID)
	if att.CbCredentialID > 0 {
		copy(credID, unsafe.Slice(att.PbCredentialID, int(att.CbCredentialID)))
	}
	fmt.Printf("   Credential ID (%d bytes): %s\n", len(credID), hex.EncodeToString(credID))

	procFreeAttestation.Call(uintptr(unsafe.Pointer(att)))

	// --- Step 2: GetAssertion against the credential we just registered ---
	fmt.Println("\n-- Step 2: WebAuthNAuthenticatorGetAssertion (tap your security key again)")

	challenge2 := random(32)
	cdBytes2 := clientDataBytes("get", hex.EncodeToString(challenge2))
	cd2 := clientData{
		Version:          clientDataCurrentVersion,
		CbClientDataJSON: uint32(len(cdBytes2)),
		PbClientDataJSON: bytePtr(cdBytes2),
		HashAlgID:        hashAlgSHA256,
	}
	allowed := credential{
		Version:        credentialCurrentVersion,
		CbID:           uint32(len(credID)),
		PbID:           bytePtr(credID),
		CredentialType: credTypePublicKey,
	}
	allowList := credentials{
		Count:       1,
		Credentials: &allowed,
	}
	gaOpts := getAssertionOptions{
		Version:                 getAssertionOptionsVersion1,
		TimeoutMS:               timeoutMs,
		AllowList:               allowList,
		AuthenticatorAttachment: attachmentCrossPlatform,
		UserVerificationReq:     uvRequirementRequired,
	}

	var asn *assertion
	start = time.Now()
	hr, _, _ = procGetAssertion.Call(
		hwnd,
		uintptr(unsafe.Pointer(rpID)),
		uintptr(unsafe.Pointer(&cd2)),
		uintptr(unsafe.Pointer(&gaOpts)),
		uintptr(unsafe.Pointer(&asn)),
	)
	elapsed = time.Since(start)
	fmt.Printf("   HRESULT=0x%08x  (%s)  elapsed=%s\n", uint32(hr), hrName(hr), elapsed)
	if hr != 0 || asn == nil {
		fmt.Println("   ABORT: GetAssertion failed.")
		return
	}
	fmt.Printf("   Returned credential id matches: %v\n",
		hex.EncodeToString(unsafe.Slice(asn.Credential.PbID, int(asn.Credential.CbID))) ==
			hex.EncodeToString(credID))
	fmt.Printf("   Signature length: %d bytes\n", asn.CbSignature)
	fmt.Printf("   Authenticator data length: %d bytes\n", asn.CbAuthenticatorData)

	procFreeAssertion.Call(uintptr(unsafe.Pointer(asn)))

	fmt.Println("\nWebAuthn round-trip complete. Both make + assert succeeded.")
}
