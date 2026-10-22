package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/shm"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

func EnsureDaemonRunning(ctx context.Context) (*shm.DaemonState, error) {
	if st, err := readStateFromShm(); err == nil {
		if err := tryHealth(ctx, st); err == nil {
			return st, nil
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}

	if err := startDaemon(exe, utils.DaemonSysProcAttrs(), startCmd); err != nil {
		return nil, err
	}

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

func startCmd(cmd *exec.Cmd) error { return cmd.Start() }

func startDaemon(exe string, attrs []*syscall.SysProcAttr, start func(*exec.Cmd) error) error {
	var errs []error
	for _, attr := range attrs {
		cmd := exec.Command(exe, "--daemon")
		cmd.SysProcAttr = attr
		if err := start(cmd); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("failed to start daemon: %w", errors.Join(errs...))
}
