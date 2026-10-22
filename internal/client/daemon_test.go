package client

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestStartDaemonUsesFirstAttrThatStarts(t *testing.T) {
	first := &syscall.SysProcAttr{}
	second := &syscall.SysProcAttr{}
	var tried []*syscall.SysProcAttr
	start := func(cmd *exec.Cmd) error {
		tried = append(tried, cmd.SysProcAttr)
		if cmd.SysProcAttr == first {
			return errors.New("access denied")
		}
		return nil
	}

	if err := startDaemon("getsec", []*syscall.SysProcAttr{first, second}, start); err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	if len(tried) != 2 || tried[0] != first || tried[1] != second {
		t.Fatalf("unexpected attempts: %v", tried)
	}
}

func TestStartDaemonStopsAfterSuccess(t *testing.T) {
	calls := 0
	start := func(cmd *exec.Cmd) error {
		calls++
		if len(cmd.Args) != 2 || cmd.Args[1] != "--daemon" {
			t.Fatalf("unexpected args: %v", cmd.Args)
		}
		return nil
	}

	attrs := []*syscall.SysProcAttr{{}, {}}
	if err := startDaemon("getsec", attrs, start); err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one attempt, got %d", calls)
	}
}

func TestStartDaemonReportsAllFailures(t *testing.T) {
	n := 0
	start := func(*exec.Cmd) error {
		n++
		return errors.New("attempt failed " + string(rune('0'+n)))
	}

	err := startDaemon("getsec", []*syscall.SysProcAttr{{}, {}}, start)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"attempt failed 1", "attempt failed 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q misses %q", err, want)
		}
	}
}
