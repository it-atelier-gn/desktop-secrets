package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	ps "github.com/mitchellh/go-ps"
)

// DetectShell returns one of: "sh", "pwsh", "cmd".
func DetectShell() string {
	// Walk ancestor processes first (works on Windows and Unix)
	if proc, err := ps.FindProcess(os.Getpid()); err == nil && proc != nil {
		// Walk up parents
		cur := proc
		for cur != nil && cur.Pid() != 0 {
			name := strings.ToLower(filepath.Base(cur.Executable()))
			switch name {
			case "cmd.exe", "cmd":
				return "cmd"
			case "pwsh.exe", "powershell.exe", "pwsh", "powershell":
				return "pwsh"
			case "bash", "zsh", "sh":
				return "sh"
			}
			cur, _ = ps.FindProcess(cur.PPid())
		}
	}

	// Windows-specific fallbacks and heuristics
	if runtime.GOOS == "windows" {
		// If COMSPEC points to cmd.exe, prefer cmd
		if strings.Contains(strings.ToLower(strings.TrimSpace(os.Getenv("COMSPEC"))), "cmd.exe") {
			return "cmd"
		}
		// If PowerShell environment hints exist, prefer pwsh
		if os.Getenv("PSModulePath") != "" || os.Getenv("PWSh") != "" || os.Getenv("PSExecutionPolicyPreference") != "" {
			return "pwsh"
		}
		return "cmd"
	}

	// Non-windows: inspect $SHELL
	shellEnv := strings.ToLower(strings.TrimSpace(os.Getenv("SHELL")))
	if strings.Contains(shellEnv, "pwsh") || strings.Contains(shellEnv, "powershell") {
		return "pwsh"
	}
	if shellEnv == "" || strings.Contains(shellEnv, "bash") || strings.Contains(shellEnv, "zsh") || strings.Contains(shellEnv, "sh") {
		return "sh"
	}
	return "sh"
}
