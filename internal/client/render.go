package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/ipc"
	"github.com/it-atelier-gn/desktop-secrets/internal/shm"
)

// Render by calling the daemon: send the .env.tpl content and read result.
// Warnings is the count of provider lines the daemon could not resolve
// (parsed from X-EnvTray-Warnings); the corresponding lines appear in
// body as "# KEY=<unresolved: ...>" comments instead of definitions.
// Callers that need strict success — e.g. getsec on a single secret —
// should treat Warnings > 0 as failure.
func RenderViaDaemon(ctx context.Context, st *shm.DaemonState, tpl []byte) (body []byte, warnings int, err error) {
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
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("render failed: %s", bytes.TrimSpace(b))
	}
	if v := resp.Header.Get("X-EnvTray-Warnings"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil {
			warnings = n
		}
	}
	body, err = io.ReadAll(resp.Body)
	return body, warnings, err
}
