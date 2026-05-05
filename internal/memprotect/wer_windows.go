//go:build windows

package memprotect

import "golang.org/x/sys/windows"

// DisableErrorReporting suppresses Windows error dialogs and the JIT
// debugger for the current process. This reduces the chance that secrets
// in memory end up in a Windows Error Reporting minidump if the daemon
// crashes.
//
// Note: this does not fully opt out of WER. For full opt-out, the daemon
// binary should additionally be registered via WerAddExcludedApplication
// or the system policy "DisableWindowsErrorReporting" must be set. Document
// this for high-assurance deployments.
func DisableErrorReporting() {
	const (
		semFailCriticalErrors = 0x0001
		semNoGPFaultErrorBox  = 0x0002
		semNoOpenFileErrorBox = 0x8000
	)
	windows.SetErrorMode(semFailCriticalErrors | semNoGPFaultErrorBox | semNoOpenFileErrorBox)
}
