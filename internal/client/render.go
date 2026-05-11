package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/ipc"
	"github.com/it-atelier-gn/desktop-secrets/internal/shm"
)

// Render by calling the daemon: send the .env.tpl content and read result.
func RenderViaDaemon(ctx context.Context, st *shm.DaemonState, tpl []byte) ([]byte, error) {
	endpoint := st.Endpoint
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return ipc.Dial(ctx, "", endpoint)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 120 * time.Second}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://ipc/render", bytes.NewReader(tpl))
	req.Header.Set("X-DesktopSecrets-Token", st.Token)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("render failed: %s", bytes.TrimSpace(b))
	}
	return io.ReadAll(resp.Body)
}
