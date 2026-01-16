package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

func quoteForSh(v string) string {
	if v == "" {
		return "''"
	}
	if !strings.ContainsAny(v, " \t'\"\\$`") {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

func quoteForPowerShell(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func quoteForCmd(v string) string {
	if v == "" {
		return `""`
	}
	if !strings.ContainsAny(v, " \t\"") {
		return v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

func printEnvCommandsAll(envMap map[string]string) {
	fmt.Println("# POSIX shell (bash, sh, zsh):")
	for k, v := range envMap {
		fmt.Printf("export %s=%s\n", k, quoteForSh(v))
	}
	fmt.Println()
	fmt.Println("# PowerShell (Windows and PowerShell Core):")
	for k, v := range envMap {
		fmt.Printf("$Env:%s = %s\n", k, quoteForPowerShell(v))
	}
	fmt.Println()
	fmt.Println("# Windows cmd.exe:")
	for k, v := range envMap {
		fmt.Printf("set %s=%s\n", k, quoteForCmd(v))
	}
}

func printEnvForShell(envMap map[string]string, shell string) {
	switch shell {
	case "sh":
		fmt.Println("# POSIX shell (bash, sh, zsh):")
		for k, v := range envMap {
			fmt.Printf("export %s=%s\n", k, quoteForSh(v))
		}
	case "pwsh":
		fmt.Println("# PowerShell (pwsh / powershell):")
		for k, v := range envMap {
			fmt.Printf("$Env:%s = %s\n", k, quoteForPowerShell(v))
		}
	case "cmd":
		fmt.Println("# Windows cmd.exe:")
		for k, v := range envMap {
			fmt.Printf("set %s=%s\n", k, quoteForCmd(v))
		}
	default:
		// fallback: print all
		printEnvCommandsAll(envMap)
	}
}

// filterEnv returns a new map containing only keys allowed by onlyList and not in excludeList.
// If onlyList is empty, all keys are considered allowed before exclusion.
func filterEnv(m map[string]string, onlyList, excludeList []string) map[string]string {
	out := make(map[string]string, len(m))
	onlySet := make(map[string]struct{})
	excludeSet := make(map[string]struct{})

	for _, k := range onlyList {
		k = strings.TrimSpace(k)
		if k != "" {
			onlySet[k] = struct{}{}
		}
	}
	for _, k := range excludeList {
		k = strings.TrimSpace(k)
		if k != "" {
			excludeSet[k] = struct{}{}
		}
	}

	for k, v := range m {
		if len(onlySet) > 0 {
			if _, ok := onlySet[k]; !ok {
				continue
			}
		}
		if _, ex := excludeSet[k]; ex {
			continue
		}
		out[k] = v
	}
	return out
}

func printJSON(envMap map[string]string) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envMap); err != nil {
		log.Fatalf("failed to encode json: %v", err)
	}
}

func oneLinerForShell(shell, exeName string) string {
	// exeName should be the command the user runs (e.g., "tplenv" or "desktopsecrets").
	// We include --shell explicitly to ensure deterministic output.
	switch shell {
	case "sh":
		// POSIX: eval "$(exe --shell=sh env)"
		return fmt.Sprintf(`eval "$(%s --shell=sh env)"`, exeName)
	case "pwsh":
		// PowerShell: exe --shell=pwsh env | Invoke-Expression
		return fmt.Sprintf(`%s --shell=pwsh env | Invoke-Expression`, exeName)
	case "cmd":
		// cmd.exe interactive: for /f "delims=" %L in ('exe --shell=cmd env') do @%L
		// Note: inside a batch file you must double the % to %%L.
		return fmt.Sprintf(`for /f "delims=" %L in ('%s --shell=cmd env') do @%L`, "%", exeName)
	default:
		// fallback: show all three suggestions
		return fmt.Sprintf("# POSIX: eval \"$(%s env)\"\n# PowerShell: %s env | Invoke-Expression\n# cmd: for /f \"delims=\" %%L in ('%s env') do @%%L", exeName, exeName, exeName)
	}
}
