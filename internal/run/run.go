package run

import (
	"fmt"
	"os"
	"os/exec"
)

func RunCommandWithEnv(cmdName string, cmdArgs []string, env map[string]string) error {
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	merged := os.Environ()
	for k, v := range env {
		merged = append(merged, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = merged

	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
