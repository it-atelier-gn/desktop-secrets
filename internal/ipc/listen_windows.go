//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strings"

	"github.com/Microsoft/go-winio"
)

// Listen creates a new named pipe and returns the listener and its
// public endpoint string. ACL restricts access to the current user.
func Listen() (net.Listener, Endpoint, error) {
	name := fmt.Sprintf(`\\.\pipe\desktop-secrets-%s`, randomToken())

	sd, err := currentUserSDDL()
	if err != nil {
		return nil, "", fmt.Errorf("build pipe SDDL: %w", err)
	}

	cfg := &winio.PipeConfig{
		SecurityDescriptor: sd,
		MessageMode:        false,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}
	ln, err := winio.ListenPipe(name, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("ListenPipe: %w", err)
	}
	return ln, Endpoint(name), nil
}

// Dial connects to the given pipe. Network argument is ignored; addr
// must be the pipe path.
func Dial(ctx context.Context, _ string, addr string) (net.Conn, error) {
	c, err := winio.DialPipeContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// currentUserSDDL builds a security descriptor restricting the pipe
// to the current user (and SYSTEM).
func currentUserSDDL() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	sid := strings.TrimSpace(u.Uid)
	if sid == "" {
		return "", fmt.Errorf("empty user SID")
	}
	// Owner: current user; DACL: GenericAll for current user + SYSTEM,
	// no other ACEs.
	return fmt.Sprintf("O:%sG:%sD:(A;;GA;;;%s)(A;;GA;;;SY)", sid, sid, sid), nil
}
