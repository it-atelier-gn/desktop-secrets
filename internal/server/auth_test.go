package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServerForAuthTest(t *testing.T) *DaemonServer {
	t.Helper()
	ds, err := NewDaemonServer(&AppState{}, "good-token-aaaa")
	if err != nil {
		t.Fatalf("NewDaemonServer: %v", err)
	}
	t.Cleanup(func() { _ = ds.ln.Close() })
	return ds
}

func TestAuthAcceptsCorrectToken(t *testing.T) {
	ds := newServerForAuthTest(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-DesktopSecrets-Token", "good-token-aaaa")

	handler := ds.auth(ds.handleHealth)
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d want 200", rec.Code)
	}
}

func TestAuthRejectsBadToken(t *testing.T) {
	ds := newServerForAuthTest(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-DesktopSecrets-Token", "bad-token-xxxx")

	handler := ds.auth(ds.handleHealth)
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestAuthRejectsMissingToken(t *testing.T) {
	ds := newServerForAuthTest(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	handler := ds.auth(ds.handleHealth)
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestAuthRejectsTokenSubstring(t *testing.T) {
	// Constant-time compare must reject prefix/suffix matches and length-mismatched
	// strings.
	ds := newServerForAuthTest(t)
	for _, bad := range []string{"good", "good-token", "good-token-aaaaa", ""} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("X-DesktopSecrets-Token", bad)
		ds.auth(ds.handleHealth)(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d want 401", bad, rec.Code)
		}
	}
}

func TestSplitLinesPreserve(t *testing.T) {
	got := splitLinesPreserve("a\r\nb\nc")
	want := []string{"a", "b", "c"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v want %v", got, want)
	}
}
