package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/ipc"
	"github.com/it-atelier-gn/desktop-secrets/internal/shm"
)

// Try a quick health check to an existing daemon.
func tryHealth(ctx context.Context, st *shm.DaemonState) error {
	endpoint := st.Endpoint
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return ipc.Dial(ctx, "", endpoint)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 800 * time.Millisecond}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ipc/health", nil)
	req.Header.Set("X-DesktopSecrets-Token", st.Token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("health status %d", resp.StatusCode)
	}
	return nil
}
