//go:build windows

package osauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	rpEntityInfoCurrentVersion   = 1
	userEntityInfoCurrentVersion = 1
	clientDataCurrentVersion     = 1
	coseCredParamCurrentVersion  = 1
	credentialCurrentVersion     = 1
	makeCredOptionsVersion1      = 1
	getAssertionOptionsVersion1  = 1

	attachmentAny = 0

	uvRequirementRequired = 1

	attestationNone = 1

	coseAlgES256 = -7

	waTimeoutMs = 60_000
)

var (
	waCredTypePublicKey, _ = windows.UTF16PtrFromString("public-key")
	waHashAlgSHA256, _     = windows.UTF16PtrFromString("SHA-256")
	waRPID, _              = windows.UTF16PtrFromString("desktop-secrets.local")
	waRPName, _            = windows.UTF16PtrFromString("Desktop Secrets")
	waUserName, _          = windows.UTF16PtrFromString("desktop-secrets")
	waUserDisplayName, _   = windows.UTF16PtrFromString("Desktop Secrets")
)

type waRPEntity struct {
	Version uint32
	ID      *uint16
	Name    *uint16
	Icon    *uint16
}

type waUserEntity struct {
	Version     uint32
	CbID        uint32
	PbID        *byte
	Name        *uint16
	Icon        *uint16
	DisplayName *uint16
}

type waCoseParam struct {
	Version uint32
	Type    *uint16
	Alg     int32
}

type waCoseParams struct {
	Count  uint32
	Params *waCoseParam
}

type waClientData struct {
	Version uint32
	CbJSON  uint32
	PbJSON  *byte
	HashAlg *uint16
}

type waCredential struct {
	Version uint32
	CbID    uint32
	PbID    *byte
	Type    *uint16
}

type waCredentials struct {
	Count   uint32
	Entries *waCredential
}

type waExtensions struct {
	Count uint32
	Ptr   uintptr
}

type waMakeOpts struct {
	Version                uint32
	TimeoutMS              uint32
	ExcludeList            waCredentials
	Extensions             waExtensions
	Attachment             uint32
	RequireResidentKey     uint32
	UserVerification       uint32
	AttestationConveyance  uint32
	Flags                  uint32
}

type waAssertOpts struct {
	Version          uint32
	TimeoutMS        uint32
	AllowList        waCredentials
	Extensions       waExtensions
	Attachment       uint32
	UserVerification uint32
	Flags            uint32
}

type waAttestation struct {
	Version             uint32
	FormatType          *uint16
	CbAuthData          uint32
	PbAuthData          *byte
	CbAttestation       uint32
	PbAttestation       *byte
	DecodeType          uint32
	DecodePtr           uintptr
	CbAttObject         uint32
	PbAttObject         *byte
	CbCredentialID      uint32
	PbCredentialID      *byte
}

type waAssertion struct {
	Version    uint32
	CbAuthData uint32
	PbAuthData *byte
	CbSig      uint32
	PbSig      *byte
	Credential waCredential
	CbUserID   uint32
	PbUserID   *byte
}

var (
	modWebAuthn        = windows.NewLazySystemDLL("webauthn.dll")
	procWAMakeCred     = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procWAFreeAttest   = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procWAGetAssertion = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procWAFreeAssert   = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procWAErrName      = modWebAuthn.NewProc("WebAuthNGetErrorName")
	procWAGetAPIVer    = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")

	modUser32             = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWnd  = modUser32.NewProc("GetForegroundWindow")
	procGetDesktopWnd     = modUser32.NewProc("GetDesktopWindow")
)

var (
	ErrWebAuthnUnavailable = errors.New("osauth: webauthn.dll unavailable")
	ErrWebAuthnCanceled    = errors.New("osauth: WebAuthn user canceled or timed out")
)

func waBytePtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

func waErrName(hr uintptr) string {
	if procWAErrName.Find() != nil {
		return ""
	}
	r, _, _ := procWAErrName.Call(hr)
	if r == 0 {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(r)))
}

func currentParentHWND() uintptr {
	h, _, _ := procGetForegroundWnd.Call()
	if h != 0 {
		return h
	}
	h, _, _ = procGetDesktopWnd.Call()
	return h
}

func waClientDataJSON(op, challenge string) []byte {
	return []byte(fmt.Sprintf(
		`{"type":"webauthn.%s","challenge":%q,"origin":"https://desktop-secrets.local","crossOrigin":false}`,
		op, challenge,
	))
}

func WebAuthnAPIAvailable() bool {
	if err := procWAGetAPIVer.Find(); err != nil {
		return false
	}
	v, _, _ := procWAGetAPIVer.Call()
	return v > 0
}

func MakeWebAuthnCredential() (credID, pubKey []byte, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !WebAuthnAPIAvailable() {
		return nil, nil, ErrWebAuthnUnavailable
	}

	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, nil, err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, err
	}
	cdBytes := waClientDataJSON("create", hex.EncodeToString(challenge))

	rp := waRPEntity{Version: rpEntityInfoCurrentVersion, ID: waRPID, Name: waRPName}
	user := waUserEntity{
		Version:     userEntityInfoCurrentVersion,
		CbID:        uint32(len(userID)),
		PbID:        waBytePtr(userID),
		Name:        waUserName,
		DisplayName: waUserDisplayName,
	}
	cd := waClientData{
		Version: clientDataCurrentVersion,
		CbJSON:  uint32(len(cdBytes)),
		PbJSON:  waBytePtr(cdBytes),
		HashAlg: waHashAlgSHA256,
	}
	param := waCoseParam{
		Version: coseCredParamCurrentVersion,
		Type:    waCredTypePublicKey,
		Alg:     coseAlgES256,
	}
	params := waCoseParams{Count: 1, Params: &param}
	opts := waMakeOpts{
		Version:               makeCredOptionsVersion1,
		TimeoutMS:             waTimeoutMs,
		Attachment:            attachmentAny,
		RequireResidentKey:    0,
		UserVerification:      uvRequirementRequired,
		AttestationConveyance: attestationNone,
	}

	var att *waAttestation
	hr, _, _ := procWAMakeCred.Call(
		currentParentHWND(),
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&att)),
	)
	if hr != 0 || att == nil {
		name := waErrName(hr)
		return nil, nil, fmt.Errorf("WebAuthNAuthenticatorMakeCredential failed: HRESULT=0x%08x (%s)", uint32(hr), name)
	}
	defer procWAFreeAttest.Call(uintptr(unsafe.Pointer(att)))

	credID = make([]byte, att.CbCredentialID)
	if att.CbCredentialID > 0 {
		copy(credID, unsafe.Slice(att.PbCredentialID, int(att.CbCredentialID)))
	}

	pubKey, err = extractCOSEFromAuthData(unsafe.Slice(att.PbAuthData, int(att.CbAuthData)))
	if err != nil {
		return nil, nil, fmt.Errorf("could not extract public key from attestation: %w", err)
	}
	return credID, pubKey, nil
}

func VerifyWebAuthn(credID []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !WebAuthnAPIAvailable() {
		return ErrWebAuthnUnavailable
	}
	if len(credID) == 0 {
		return errors.New("osauth: empty credential ID")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	cdBytes := waClientDataJSON("get", hex.EncodeToString(challenge))
	cd := waClientData{
		Version: clientDataCurrentVersion,
		CbJSON:  uint32(len(cdBytes)),
		PbJSON:  waBytePtr(cdBytes),
		HashAlg: waHashAlgSHA256,
	}
	allowed := waCredential{
		Version: credentialCurrentVersion,
		CbID:    uint32(len(credID)),
		PbID:    waBytePtr(credID),
		Type:    waCredTypePublicKey,
	}
	allowList := waCredentials{Count: 1, Entries: &allowed}
	opts := waAssertOpts{
		Version:          getAssertionOptionsVersion1,
		TimeoutMS:        waTimeoutMs,
		AllowList:        allowList,
		Attachment:       attachmentAny,
		UserVerification: uvRequirementRequired,
	}

	var asn *waAssertion
	hr, _, _ := procWAGetAssertion.Call(
		currentParentHWND(),
		uintptr(unsafe.Pointer(waRPID)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&asn)),
	)
	if hr != 0 || asn == nil {
		name := waErrName(hr)
		if isWAUserCanceled(hr) {
			return ErrWebAuthnCanceled
		}
		return fmt.Errorf("WebAuthNAuthenticatorGetAssertion failed: HRESULT=0x%08x (%s)", uint32(hr), name)
	}
	defer procWAFreeAssert.Call(uintptr(unsafe.Pointer(asn)))
	return nil
}

func isWAUserCanceled(hr uintptr) bool {
	const ntStatusCanceled = 0xC0000120
	switch uint32(hr) {
	case 0x800704C7,
		ntStatusCanceled,
		0x80004004:
		return true
	}
	return false
}

func extractCOSEFromAuthData(authData []byte) ([]byte, error) {
	if len(authData) < 37 {
		return nil, errors.New("authData too short for header")
	}
	flags := authData[32]
	if flags&0x40 == 0 {
		return nil, errors.New("attested credential data flag not set")
	}
	off := 37
	if len(authData) < off+18 {
		return nil, errors.New("authData too short for attested credential header")
	}
	credIDLen := int(authData[off+16])<<8 | int(authData[off+17])
	off += 18 + credIDLen
	if len(authData) < off {
		return nil, errors.New("authData truncated inside credentialId")
	}
	out := make([]byte, len(authData)-off)
	copy(out, authData[off:])
	return out, nil
}
