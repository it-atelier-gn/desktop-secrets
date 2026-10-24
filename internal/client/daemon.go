package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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

	if err := startDaemon(exe, utils.DaemonLaunchers(), os.Stderr); err != nil {
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

func startDaemon(exe string, launchers []utils.DaemonLauncher, warn io.Writer) error {
	var errs []error
	for _, l := range launchers {
		var env []string
		if len(errs) > 0 {
			env = []string{utils.StartFailuresEnv + "=" + joinErrors(errs)}
		}
		if err := l.Start(exe, []string{"--daemon"}, env); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", l.Name, err))
			continue
		}
		if l.Degraded {
			fmt.Fprintf(warn, "warning: daemon started %s after: %s; it may stop when the calling process ends and unlocked vaults are then forgotten\n",
				l.Name, joinErrors(errs))
		}
		return nil
	}
	return fmt.Errorf("failed to start daemon: %w", errors.Join(errs...))
}

func joinErrors(errs []error) string {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}
