package client

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

type fakeLaunch struct {
	name string
	args []string
	env  []string
}

func fakeLaunchers(calls *[]fakeLaunch, fail map[string]bool, degraded string, names ...string) []utils.DaemonLauncher {
	var out []utils.DaemonLauncher
	for _, n := range names {
		out = append(out, utils.DaemonLauncher{
			Name:     n,
			Degraded: n == degraded,
			Start: func(exe string, args, env []string) error {
				*calls = append(*calls, fakeLaunch{name: n, args: args, env: env})
				if fail[n] {
					return errors.New(n + " denied")
				}
				return nil
			},
		})
	}
	return out
}

func TestStartDaemonFallsThroughToNextLauncher(t *testing.T) {
	var calls []fakeLaunch
	var warn bytes.Buffer
	ls := fakeLaunchers(&calls, map[string]bool{"breakaway": true}, "", "breakaway", "scheduler", "detached")

	if err := startDaemon("getsec", ls, &warn); err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	if len(calls) != 2 || calls[0].name != "breakaway" || calls[1].name != "scheduler" {
		t.Fatalf("unexpected attempts: %+v", calls)
	}
	if len(calls[0].env) != 0 {
		t.Fatalf("first attempt must not carry failures: %v", calls[0].env)
	}
	want := utils.StartFailuresEnv + "=breakaway: breakaway denied"
	if len(calls[1].env) != 1 || calls[1].env[0] != want {
		t.Fatalf("second attempt env = %v, want %q", calls[1].env, want)
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warning: %q", warn.String())
	}
}

func TestStartDaemonPassesDaemonFlag(t *testing.T) {
	var calls []fakeLaunch
	ls := fakeLaunchers(&calls, nil, "", "a", "b")
	if err := startDaemon("getsec", ls, &bytes.Buffer{}); err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	if len(calls) != 1 || len(calls[0].args) != 1 || calls[0].args[0] != "--daemon" {
		t.Fatalf("unexpected attempts: %+v", calls)
	}
}

func TestStartDaemonWarnsOnDegradedStart(t *testing.T) {
	var calls []fakeLaunch
	var warn bytes.Buffer
	ls := fakeLaunchers(&calls, map[string]bool{"breakaway": true, "scheduler": true}, "detached", "breakaway", "scheduler", "detached")

	if err := startDaemon("getsec", ls, &warn); err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	for _, want := range []string{"detached", "breakaway denied", "scheduler denied"} {
		if !strings.Contains(warn.String(), want) {
			t.Fatalf("warning %q misses %q", warn.String(), want)
		}
	}
}

func TestStartDaemonReportsAllFailures(t *testing.T) {
	var calls []fakeLaunch
	ls := fakeLaunchers(&calls, map[string]bool{"a": true, "b": true}, "", "a", "b")

	err := startDaemon("getsec", ls, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"a: a denied", "b: b denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q misses %q", err, want)
		}
	}
}
