package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type DaemonServer struct {
	App   *AppState
	Port  int
	token string
	srv   *http.Server
	ln    net.Listener // pre-bound listener to avoid races
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
		// Addr is for logging/diagnostics; Serve will use ds.ln directly.
		// We will fill this after we learn the selected port.
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// Bind to any free port on IPv4 localhost. Fallback to IPv6 if needed.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
		if err != nil {
			return nil, fmt.Errorf("cannot find free port: %w", err)
		}
	}
	ds.ln = ln

	// Capture the chosen port and set Addr for clarity.
	addr := ln.Addr().(*net.TCPAddr)
	ds.Port = addr.Port
	ds.srv.Addr = fmt.Sprintf("127.0.0.1:%d", ds.Port)

	return ds, nil
}

func (ds *DaemonServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-DesktopSecrets-Token") != ds.token {
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
	ctx := context.Background()
	rendered, errs := ResolveEnvLines(ctx, ds.App, lines)

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
	// Serve on the pre-bound listener to remove race between probing and serving.
	if ds.ln != nil {
		return ds.srv.Serve(ds.ln)
	}
	// Fallback (shouldn’t happen with Variant A):
	ln, err := net.Listen("tcp4", ds.srv.Addr)
	if err != nil {
		return err
	}
	return ds.srv.Serve(ln)
}

func (ds *DaemonServer) Shutdown(ctx context.Context) error {
	// http.Server.Shutdown will stop accepting new connections and close the listener.
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
