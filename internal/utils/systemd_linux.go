//go:build linux

package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const systemdDaemonUnit = "desktop-secrets-daemon"

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func startSystemdDaemon(exe string, args, env []string) error {
	return startSystemdUnit(systemdDaemonUnit, exe, args, env)
}

func startSystemdUnit(unit, exe string, args, env []string) error {
	path, err := exec.LookPath("systemd-run")
	if err != nil {
		return err
	}
	full := append(os.Environ(), env...)
	cmd := exec.Command(path, systemdRunArgs(unit, exe, args, full)...)
	cmd.Env = full
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func systemdRunArgs(unit, exe string, args, env []string) []string {
	out := []string{
		"--user",
		"--quiet",
		"--collect",
		"--same-dir",
		"--unit=" + unit,
		"--description=desktop-secrets daemon",
		"--property=Type=exec",
	}
	seen := map[string]bool{}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !envName.MatchString(k) || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, "--setenv="+k)
	}
	out = append(out, "--", exe)
	return append(out, args...)
}
