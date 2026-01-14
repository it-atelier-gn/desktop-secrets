package client

import (
	"context"
	"desktopsecrets/internal/shm"
	"fmt"
	"net/http"
	"time"
)

// Try a quick health check to an existing daemon.
func tryHealth(ctx context.Context, st *shm.DaemonState) error {
	client := &http.Client{Timeout: 800 * time.Millisecond}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/health", st.Port), nil)
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
