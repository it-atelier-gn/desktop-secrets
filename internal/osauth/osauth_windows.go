//go:build windows

package osauth

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file talks to the WinRT class
// Windows.Security.Credentials.UI.UserConsentVerifier directly via
// combase.dll. We avoid pulling in a codegen-based WinRT binding
// library — the surface we need (one static factory, one async call,
// one enum result) is small enough to hand-roll.
//
// The dialog UserConsentVerifier renders is the same surface Windows
// Hello uses elsewhere: face / fingerprint where supported, falling
// back to a Windows-Hello PIN (TPM-backed). It is *not* a regular
// user-space window — keystroke / mouse injection from a sibling
// process running as the same user does not satisfy it.

const (
	roInitMultithreaded = 1

	asyncStatusStarted   = 0
	asyncStatusCompleted = 1

	// UserConsentVerificationResult, from
	// Windows.Security.Credentials.UI. 0 means Verified.
	uvResultVerified = 0
)

var (
	modCombase = windows.NewLazySystemDLL("combase.dll")

	procRoInitialize           = modCombase.NewProc("RoInitialize")
	procRoGetActivationFactory = modCombase.NewProc("RoGetActivationFactory")
	procWindowsCreateString    = modCombase.NewProc("WindowsCreateString")
	procWindowsDeleteString    = modCombase.NewProc("WindowsDeleteString")
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// IID_IUserConsentVerifierStatics = AF4F3F91-564C-4DDC-B8B5-973447627C65
var iidUserConsentVerifierStatics = guid{
	0xAF4F3F91, 0x564C, 0x4DDC,
	[8]byte{0xB8, 0xB5, 0x97, 0x34, 0x47, 0x62, 0x7C, 0x65},
}

// IID_IAsyncInfo = 00000036-0000-0000-C000-000000000046
var iidAsyncInfo = guid{
	0x00000036, 0x0000, 0x0000,
	[8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46},
}

type iUserConsentVerifierStaticsVtbl struct {
	// IUnknown
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	// IInspectable
	GetIids             uintptr
	GetRuntimeClassName uintptr
	GetTrustLevel       uintptr
	// IUserConsentVerifierStatics
	CheckAvailabilityAsync   uintptr
	RequestVerificationAsync uintptr
}

type iUserConsentVerifierStatics struct {
	Vtbl *iUserConsentVerifierStaticsVtbl
}

type iAsyncInfoVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	GetIids             uintptr
	GetRuntimeClassName uintptr
	GetTrustLevel       uintptr
	GetId               uintptr
	GetStatus           uintptr
	GetErrorCode        uintptr
	Cancel              uintptr
	Close               uintptr
}

type iAsyncInfo struct {
	Vtbl *iAsyncInfoVtbl
}

type iAsyncOperationVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	GetIids             uintptr
	GetRuntimeClassName uintptr
	GetTrustLevel       uintptr
	SetCompleted        uintptr
	GetCompleted        uintptr
	GetResults          uintptr
}

type iAsyncOperation struct {
	Vtbl *iAsyncOperationVtbl
}

func hrErr(stage string, hr uintptr) error {
	return fmt.Errorf("osauth: %s failed (HRESULT=0x%08x)", stage, uint32(hr))
}

func createHString(s string) (uintptr, error) {
	if s == "" {
		// HSTRING for an empty string is 0/NULL — valid in WinRT.
		return 0, nil
	}
	u16, err := windows.UTF16FromString(s)
	if err != nil {
		return 0, err
	}
	// length is in UTF-16 code units, excluding the null terminator.
	n := len(u16) - 1
	var h uintptr
	hr, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(n),
		uintptr(unsafe.Pointer(&h)),
	)
	if hr != 0 {
		return 0, hrErr("WindowsCreateString", hr)
	}
	return h, nil
}

func deleteHString(h uintptr) {
	if h == 0 {
		return
	}
	_, _, _ = procWindowsDeleteString.Call(h)
}

func roInit() {
	// S_OK (0), S_FALSE (1), and RPC_E_CHANGED_MODE / already-init are
	// all acceptable: if the host process already initialised COM /
	// WinRT we still get a working apartment.
	_, _, _ = procRoInitialize.Call(uintptr(roInitMultithreaded))
}

func getActivationFactory(className string, iid *guid) (unsafe.Pointer, error) {
	classH, err := createHString(className)
	if err != nil {
		return nil, err
	}
	defer deleteHString(classH)
	var out unsafe.Pointer
	hr, _, _ := procRoGetActivationFactory.Call(
		classH,
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&out)),
	)
	if hr != 0 {
		return nil, hrErr("RoGetActivationFactory", hr)
	}
	return out, nil
}

func (f *iUserConsentVerifierStatics) requestVerification(messageH uintptr) (*iAsyncOperation, error) {
	var op *iAsyncOperation
	hr, _, _ := syscall.SyscallN(
		f.Vtbl.RequestVerificationAsync,
		uintptr(unsafe.Pointer(f)),
		messageH,
		uintptr(unsafe.Pointer(&op)),
	)
	if hr != 0 {
		return nil, hrErr("RequestVerificationAsync", hr)
	}
	return op, nil
}

func (f *iUserConsentVerifierStatics) release() {
	_, _, _ = syscall.SyscallN(f.Vtbl.Release, uintptr(unsafe.Pointer(f)))
}

func (op *iAsyncOperation) queryAsyncInfo() (*iAsyncInfo, error) {
	var out *iAsyncInfo
	hr, _, _ := syscall.SyscallN(
		op.Vtbl.QueryInterface,
		uintptr(unsafe.Pointer(op)),
		uintptr(unsafe.Pointer(&iidAsyncInfo)),
		uintptr(unsafe.Pointer(&out)),
	)
	if hr != 0 {
		return nil, hrErr("QueryInterface(IAsyncInfo)", hr)
	}
	return out, nil
}

func (op *iAsyncOperation) getResults() (int32, error) {
	var v int32
	hr, _, _ := syscall.SyscallN(
		op.Vtbl.GetResults,
		uintptr(unsafe.Pointer(op)),
		uintptr(unsafe.Pointer(&v)),
	)
	if hr != 0 {
		return 0, hrErr("GetResults", hr)
	}
	return v, nil
}

func (op *iAsyncOperation) release() {
	_, _, _ = syscall.SyscallN(op.Vtbl.Release, uintptr(unsafe.Pointer(op)))
}

func (i *iAsyncInfo) status() (int32, error) {
	var s int32
	hr, _, _ := syscall.SyscallN(
		i.Vtbl.GetStatus,
		uintptr(unsafe.Pointer(i)),
		uintptr(unsafe.Pointer(&s)),
	)
	if hr != 0 {
		return 0, hrErr("IAsyncInfo.GetStatus", hr)
	}
	return s, nil
}

func (i *iAsyncInfo) close() {
	_, _, _ = syscall.SyscallN(i.Vtbl.Close, uintptr(unsafe.Pointer(i)))
}

func (i *iAsyncInfo) release() {
	_, _, _ = syscall.SyscallN(i.Vtbl.Release, uintptr(unsafe.Pointer(i)))
}

// verifyTimeout caps how long we wait for the user to satisfy the
// Hello prompt. 90s mirrors the dialog's own grace period; if the
// prompt times out client-side first, that's fine — we treat it as a
// failed verification.
const verifyTimeout = 90 * time.Second

// Verify shows the Windows Hello / PIN prompt and blocks until the
// user verifies, cancels, or the prompt times out.
//
// Returns FactorOSLocal on success, FactorClick + an error on
// failure. Callers should map a non-nil error to "deny + log
// os_auth_failed" rather than retrying.
//
// Safe to call from any goroutine: we lock the OS thread for the
// duration of the WinRT calls (RoInitialize is per-thread state).
func Verify(reason string) (Factor, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	roInit()

	factory, err := getActivationFactory(
		"Windows.Security.Credentials.UI.UserConsentVerifier",
		&iidUserConsentVerifierStatics,
	)
	if err != nil {
		return FactorClick, err
	}
	f := (*iUserConsentVerifierStatics)(factory)
	defer f.release()

	msgH, err := createHString(reason)
	if err != nil {
		return FactorClick, err
	}
	defer deleteHString(msgH)

	op, err := f.requestVerification(msgH)
	if err != nil {
		return FactorClick, err
	}
	defer op.release()

	info, err := op.queryAsyncInfo()
	if err != nil {
		return FactorClick, err
	}
	defer info.release()

	deadline := time.Now().Add(verifyTimeout)
	for {
		s, err := info.status()
		if err != nil {
			return FactorClick, err
		}
		if s != asyncStatusStarted {
			if s != asyncStatusCompleted {
				info.close()
				return FactorClick, ErrCanceled
			}
			break
		}
		if time.Now().After(deadline) {
			info.close()
			return FactorClick, ErrCanceled
		}
		time.Sleep(50 * time.Millisecond)
	}

	res, err := op.getResults()
	info.close()
	if err != nil {
		return FactorClick, err
	}
	if res != uvResultVerified {
		return FactorClick, ErrCanceled
	}
	return FactorOSLocal, nil
}

// Available reports whether the WinRT Windows Hello surface can be
// reached AND a credential is enrolled. Implemented as a wrapper
// around CheckAvailability so callers don't have to special-case
// "factory loads but no PIN enrolled" — the most common DeviceNotPresent
// failure mode on developer machines.
func Available() bool {
	return CheckAvailability() == AvailabilityAvailable
}

// CheckAvailability returns the live UserConsentVerifierAvailability
// state. Use this from settings UI to disable the os_local option
// when the factor cannot be satisfied (no credential enrolled, policy
// blocked, etc.) instead of letting the user pick it and only
// discovering at retrieval time.
func CheckAvailability() Availability {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	roInit()

	factory, err := getActivationFactory(
		"Windows.Security.Credentials.UI.UserConsentVerifier",
		&iidUserConsentVerifierStatics,
	)
	if err != nil {
		return AvailabilityDeviceNotPresent
	}
	f := (*iUserConsentVerifierStatics)(factory)
	defer f.release()

	var op *iAsyncOperation
	hr, _, _ := syscall.SyscallN(
		f.Vtbl.CheckAvailabilityAsync,
		uintptr(unsafe.Pointer(f)),
		uintptr(unsafe.Pointer(&op)),
	)
	if hr != 0 || op == nil {
		return AvailabilityDeviceNotPresent
	}
	defer op.release()

	info, err := op.queryAsyncInfo()
	if err != nil {
		return AvailabilityDeviceNotPresent
	}
	defer info.release()

	// CheckAvailabilityAsync completes synchronously in practice — it
	// reads cached enrollment state — but the contract is async, so
	// poll briefly with a short cap. 5s is generous for a state read.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := info.status()
		if err != nil {
			return AvailabilityDeviceNotPresent
		}
		if s != asyncStatusStarted {
			if s != asyncStatusCompleted {
				info.close()
				return AvailabilityDeviceNotPresent
			}
			break
		}
		if time.Now().After(deadline) {
			info.close()
			return AvailabilityDeviceNotPresent
		}
		time.Sleep(20 * time.Millisecond)
	}

	res, err := op.getResults()
	info.close()
	if err != nil {
		return AvailabilityDeviceNotPresent
	}
	return Availability(res)
}
