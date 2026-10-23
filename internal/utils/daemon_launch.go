package utils

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	envPrefix        = "DESKTOP_SECRETS_"
	setenvFlag       = "--setenv="
	StartFailuresEnv = envPrefix + "DAEMON_START_FAILURES"
)

type DaemonLauncher struct {
	Name     string
	Start    func(exe string, args, env []string) error
	Degraded bool
}

func spawnWith(attr *syscall.SysProcAttr) func(string, []string, []string) error {
	return func(exe string, args, env []string) error {
		cmd := exec.Command(exe, args...)
		cmd.Env = append(os.Environ(), env...)
		cmd.SysProcAttr = attr
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
}

func SetenvArgs(extra []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, kv := range append(extra, os.Environ()...) {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(strings.ToUpper(k), envPrefix) || seen[strings.ToUpper(k)] {
			continue
		}
		seen[strings.ToUpper(k)] = true
		out = append(out, setenvFlag+kv)
	}
	return out
}

func ApplySetenvArgs(args []string) {
	for _, a := range args {
		kv, ok := strings.CutPrefix(a, setenvFlag)
		if !ok {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(strings.ToUpper(k), envPrefix) {
			_ = os.Setenv(k, v)
		}
	}
}
