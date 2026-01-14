package client

import (
	"bytes"
	"context"
	"desktopsecrets/internal/shm"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Render by calling the daemon: send the .env.tpl content and read result.
func RenderViaDaemon(ctx context.Context, st *shm.DaemonState, tpl []byte) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/render", st.Port), bytes.NewReader(tpl))
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
