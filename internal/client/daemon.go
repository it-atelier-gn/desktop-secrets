package client

import (
	"context"
	"desktopsecrets/internal/shm"
	"desktopsecrets/internal/utils"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Start the daemon (tray) if it’s not running. Wait until /health OK or timeout.
func EnsureDaemonRunning(ctx context.Context) (*shm.DaemonState, error) {
	// 1) If we have shm state and health passes — we’re done.
	if st, err := readStateFromShm(); err == nil {
		if err := tryHealth(ctx, st); err == nil {
			return st, nil
		}
	}

	// 2) Spawn the daemon.
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(exe, "--daemon")

	// Detach/Hide window on Windows; fully detach on Unix.
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = utils.HideWindowSysProcAttr()
	} else {
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		cmd.SysProcAttr = utils.DetachSysProcAttr()
	}

	// Start, not wait.
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start daemon: %w", err)
	}

	// 3) Wait for shm state then health OK.
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		st, err := readStateFromShm()
		if err != nil {
			lastErr = err
			continue
		}
		if err := tryHealth(ctx, st); err != nil {
			lastErr = err
			continue
		}
		return st, nil
	}
	return nil, fmt.Errorf("daemon did not become healthy: %v", lastErr)
}
