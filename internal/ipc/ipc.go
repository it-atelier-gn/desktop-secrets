// Package ipc provides a local OS-native transport (Windows named pipe,
// Unix domain socket) carrying HTTP semantics. The peer PID of an
// accepted connection is recoverable via PeerPID, which is the whole
// reason this package exists.
package ipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
)

// Endpoint is the address string published to clients via shared memory.
// On Windows: \\.\pipe\desktop-secrets-<token>; on Unix: a path on the
// filesystem.
type Endpoint string

// Listener accepts incoming local connections.
type Listener interface {
	net.Listener
}

// Dialer is the client-side connect function. Plugged into
// http.Transport.DialContext.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// PeerPID returns the OS PID of the process at the other end of conn,
// or 0 + error when unavailable.
func PeerPID(c net.Conn) (int, error) {
	return peerPID(c)
}

// randomToken returns 16 random bytes hex-encoded; used to randomise
// the endpoint name per daemon launch.
func randomToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
