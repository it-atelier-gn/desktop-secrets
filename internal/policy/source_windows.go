//go:build windows

package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	FactorEnforced = true
	RegistryPath   = `SOFTWARE\Policies\desktop-secrets`
	Location       = `HKLM\` + RegistryPath
)

var ErrElevationCanceled = errors.New("the administrator prompt was canceled")

func Load() (Floor, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, RegistryPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return Floor{}, nil
	}
	if err != nil {
		return Floor{}, err
	}
	defer k.Close()
	var f Floor
	if v, _, err := k.GetIntegerValue("RetrievalApproval"); err == nil {
		f.RetrievalApproval = v != 0
	}
	if v, _, err := k.GetStringValue("MinApprovalFactor"); err == nil {
		f.MinApprovalFactor = normalizeFactor(v)
	}
	if v, _, err := k.GetIntegerValue("MaxUnlockTTL"); err == nil {
		f.MaxUnlockTTL = int(v)
	}
	return f, nil
}

func Save(f Floor) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, RegistryPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	approval := uint32(0)
	if f.RetrievalApproval {
		approval = 1
	}
	if err := k.SetDWordValue("RetrievalApproval", approval); err != nil {
		return err
	}
	if err := k.SetStringValue("MinApprovalFactor", normalizeFactor(f.MinApprovalFactor)); err != nil {
		return err
	}
	return k.SetDWordValue("MaxUnlockTTL", uint32(f.MaxUnlockTTL))
}

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

const seeMaskNoCloseProcess = 0x00000040

var procShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func SaveElevated(f Floor) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{SetFlag}, f.Args()...)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return ErrElevationCanceled
		}
		return err
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("writing %s failed (exit code %d)", Location, code)
	}
	return nil
}
