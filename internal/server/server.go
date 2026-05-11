package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
	"github.com/it-atelier-gn/desktop-secrets/internal/ipc"
)

// ctxKey is an unexported type for request-context keys to avoid
// collisions with other packages.
type ctxKey int

const (
	ctxKeyClientPID ctxKey = iota
)

// ClientPIDFromContext returns the peer PID associated with the
// current HTTP request, or 0 if unavailable.
func ClientPIDFromContext(ctx context.Context) int {
	v, _ := ctx.Value(ctxKeyClientPID).(int)
	return v
}

type DaemonServer struct {
	App      *AppState
	Endpoint string
	token    string
	srv      *http.Server
	ln       net.Listener
}

func NewDaemonServer(app *AppState, token string) (*DaemonServer, error) {
	mux := http.NewServeMux()
	ds := &DaemonServer{
		App:   app,
		token: token,
	}

	mux.HandleFunc("/health", ds.auth(ds.handleHealth))
	mux.HandleFunc("/render", ds.auth(ds.handleRender))

	ds.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			pid, err := ipc.PeerPID(c)
			if err != nil {
				pid = 0
			}
			ctx = context.WithValue(ctx, ctxKeyClientPID, pid)
			ctx = clientinfo.WithInfo(ctx, clientinfo.Lookup(pid))
			return ctx
		},
	}

	ln, endpoint, err := ipc.Listen()
	if err != nil {
		return nil, fmt.Errorf("ipc listen: %w", err)
	}
	ds.ln = ln
	ds.Endpoint = string(endpoint)
	ds.srv.Addr = string(endpoint)

	return ds, nil
}

func (ds *DaemonServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-DesktopSecrets-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(ds.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (ds *DaemonServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (ds *DaemonServer) handleRender(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := ioReadAllLimit(r.Body, 5<<20) // 5MB guard
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	lines := splitLinesPreserve(string(body))
	rendered, errs := ResolveEnvLines(r.Context(), ds.App, lines)

	if len(errs) > 0 {
		var sb strings.Builder
		for _, e := range errs {
			sb.WriteString(e.Error())
			sb.WriteString("\n")
		}
		w.Header().Set("X-EnvTray-Warnings", strconv.Itoa(len(errs)))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(strings.Join(rendered, "\n")))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(rendered, "\n")))
}

func (ds *DaemonServer) Serve() error {
	return ds.srv.Serve(ds.ln)
}

func (ds *DaemonServer) Shutdown(ctx context.Context) error {
	return ds.srv.Shutdown(ctx)
}

// small helpers

func ioReadAllLimit(r io.Reader, limit int64) ([]byte, error) {
	var b strings.Builder
	buf := make([]byte, 4096)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return nil, fmt.Errorf("too large")
			}
			b.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return []byte(b.String()), nil
}

func splitLinesPreserve(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}
