//go:build windows

// hellotest exercises the Windows Hello (UserConsentVerifier) path
// step-by-step and prints the result of each WinRT call. Run it from
// a console — if no dialog appears, the printed HRESULTs will tell us
// which step failed silently.
//
// Build: go build -o hellotest.exe ./cmd/hellotest
// Run:   .\hellotest.exe
package main

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
)

const (
	roInitMultithreaded = 1

	asyncStatusStarted   = 0
	asyncStatusCompleted = 1
	asyncStatusCanceled  = 2
	asyncStatusError     = 3

	uvResultVerified              = 0
	uvResultDeviceNotPresent      = 1
	uvResultNotConfiguredForUser  = 2
	uvResultDisabledByPolicy      = 3
	uvResultDeviceBusy            = 4
	uvResultRetriesExhausted      = 5
	uvResultCanceled              = 6
)

func uvResultName(v int32) string {
	switch v {
	case uvResultVerified:
		return "Verified"
	case uvResultDeviceNotPresent:
		return "DeviceNotPresent"
	case uvResultNotConfiguredForUser:
		return "NotConfiguredForUser (Hello not enrolled)"
	case uvResultDisabledByPolicy:
		return "DisabledByPolicy"
	case uvResultDeviceBusy:
		return "DeviceBusy"
	case uvResultRetriesExhausted:
		return "RetriesExhausted"
	case uvResultCanceled:
		return "Canceled"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// IUserConsentVerifierStatics
var iidUCVStatics = guid{
	0xAF4F3F91, 0x564C, 0x4DDC,
	[8]byte{0xB8, 0xB5, 0x97, 0x34, 0x47, 0x62, 0x7C, 0x65},
}

// IAsyncInfo
var iidAsyncInfo = guid{
	0x00000036, 0x0000, 0x0000,
	[8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46},
}

type ucvStaticsVtbl struct {
	QueryInterface           uintptr
	AddRef                   uintptr
	Release                  uintptr
	GetIids                  uintptr
	GetRuntimeClassName      uintptr
	GetTrustLevel            uintptr
	CheckAvailabilityAsync   uintptr
	RequestVerificationAsync uintptr
}

type ucvStatics struct {
	Vtbl *ucvStaticsVtbl
}

type asyncInfoVtbl struct {
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

type asyncInfo struct {
	Vtbl *asyncInfoVtbl
}

type asyncOpVtbl struct {
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

type asyncOp struct {
	Vtbl *asyncOpVtbl
}

var (
	modCombase                 = windows.NewLazySystemDLL("combase.dll")
	procRoInitialize           = modCombase.NewProc("RoInitialize")
	procRoGetActivationFactory = modCombase.NewProc("RoGetActivationFactory")
	procWindowsCreateString    = modCombase.NewProc("WindowsCreateString")
	procWindowsDeleteString    = modCombase.NewProc("WindowsDeleteString")
)

func mkHString(s string) (uintptr, error) {
	if s == "" {
		return 0, nil
	}
	u16, err := windows.UTF16FromString(s)
	if err != nil {
		return 0, err
	}
	n := len(u16) - 1
	var h uintptr
	hr, _, _ := procWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(n),
		uintptr(unsafe.Pointer(&h)),
	)
	if hr != 0 {
		return 0, fmt.Errorf("WindowsCreateString HRESULT=0x%08x", uint32(hr))
	}
	return h, nil
}

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fmt.Println("=== Windows Hello probe ===")
	fmt.Printf("osauth.Available() = %v\n", osauth.Available())

	fmt.Println("\n-- Step 1: RoInitialize(MULTITHREADED)")
	hr, _, _ := procRoInitialize.Call(uintptr(roInitMultithreaded))
	// S_OK=0, S_FALSE=1, RPC_E_CHANGED_MODE=0x80010106 (already STA from
	// the host). All three mean "we have an apartment" for our purposes.
	fmt.Printf("   HRESULT = 0x%08x\n", uint32(hr))

	fmt.Println("\n-- Step 2: RoGetActivationFactory(UserConsentVerifier)")
	classH, err := mkHString("Windows.Security.Credentials.UI.UserConsentVerifier")
	if err != nil {
		fmt.Println("   mkHString failed:", err)
		return
	}
	defer procWindowsDeleteString.Call(classH)

	var factory unsafe.Pointer
	hr, _, _ = procRoGetActivationFactory.Call(
		classH,
		uintptr(unsafe.Pointer(&iidUCVStatics)),
		uintptr(unsafe.Pointer(&factory)),
	)
	fmt.Printf("   HRESULT = 0x%08x  factory=%p\n", uint32(hr), factory)
	if hr != 0 || factory == nil {
		fmt.Println("   ABORT: factory lookup failed. Hello surface not reachable from this process.")
		return
	}
	f := (*ucvStatics)(factory)

	fmt.Println("\n-- Step 3: RequestVerificationAsync(\"hellotest probe\")")
	msgH, err := mkHString("hellotest probe")
	if err != nil {
		fmt.Println("   mkHString failed:", err)
		return
	}
	defer procWindowsDeleteString.Call(msgH)

	var op *asyncOp
	hr, _, _ = syscall.SyscallN(
		f.Vtbl.RequestVerificationAsync,
		uintptr(unsafe.Pointer(f)),
		msgH,
		uintptr(unsafe.Pointer(&op)),
	)
	fmt.Printf("   HRESULT = 0x%08x  op=%p\n", uint32(hr), op)
	if hr != 0 || op == nil {
		fmt.Println("   ABORT: RequestVerificationAsync rejected the call.")
		fmt.Println("   On Win32 desktop apps this often requires IInitializeWithWindow")
		fmt.Println("   to associate a window handle before the dialog can render.")
		return
	}

	fmt.Println("\n-- Step 4: QueryInterface(IAsyncInfo)")
	var ai *asyncInfo
	hr, _, _ = syscall.SyscallN(
		op.Vtbl.QueryInterface,
		uintptr(unsafe.Pointer(op)),
		uintptr(unsafe.Pointer(&iidAsyncInfo)),
		uintptr(unsafe.Pointer(&ai)),
	)
	fmt.Printf("   HRESULT = 0x%08x  info=%p\n", uint32(hr), ai)
	if hr != 0 || ai == nil {
		fmt.Println("   ABORT: cannot query IAsyncInfo")
		return
	}

	fmt.Println("\n-- Step 5: poll IAsyncInfo.GetStatus until non-Started (waiting for user)")
	deadline := time.Now().Add(90 * time.Second)
	for {
		var s int32
		hr, _, _ = syscall.SyscallN(
			ai.Vtbl.GetStatus,
			uintptr(unsafe.Pointer(ai)),
			uintptr(unsafe.Pointer(&s)),
		)
		if hr != 0 {
			fmt.Printf("   GetStatus HRESULT = 0x%08x\n", uint32(hr))
			return
		}
		if s != asyncStatusStarted {
			fmt.Printf("   final status = %d (%s)\n", s, statusName(s))
			break
		}
		if time.Now().After(deadline) {
			fmt.Println("   TIMEOUT after 90s with status=Started")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("\n-- Step 6: GetResults")
	var res int32
	hr, _, _ = syscall.SyscallN(
		op.Vtbl.GetResults,
		uintptr(unsafe.Pointer(op)),
		uintptr(unsafe.Pointer(&res)),
	)
	fmt.Printf("   HRESULT = 0x%08x  result = %d (%s)\n", uint32(hr), res, uvResultName(res))
}

func statusName(s int32) string {
	switch s {
	case asyncStatusStarted:
		return "Started"
	case asyncStatusCompleted:
		return "Completed"
	case asyncStatusCanceled:
		return "Canceled"
	case asyncStatusError:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}
