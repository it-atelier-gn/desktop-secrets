//go:build !windows && !linux && !darwin

package ipc

import (
	"fmt"
	"net"
)

func peerPID(_ net.Conn) (int, error) {
	return 0, fmt.Errorf("peer PID lookup not implemented on this platform")
}
