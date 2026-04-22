package onepassword

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestResolveSecret(t *testing.T) {
	ctx := context.Background()
	m := NewManager(time.Minute)
	var calls []string
	m.runOp = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		// echo the URI back so tests can assert on it
		return []byte("value-for-" + args[len(args)-1] + "\n"), nil
	}

	got, err := m.ResolveSecret(ctx, "Personal/GitHub", "")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got != "value-for-op://Personal/GitHub/password" {
		t.Fatalf("got %q", got)
	}

	got, err = m.ResolveSecret(ctx, "Personal/AWS", "access_key")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got != "value-for-op://Personal/AWS/access_key" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveSecret_Caches(t *testing.T) {
	ctx := context.Background()
	m := NewManager(time.Minute)
	n := 0
	m.runOp = func(_ context.Context, _ ...string) ([]byte, error) {
		n++
		return []byte("x\n"), nil
	}
	_, _ = m.ResolveSecret(ctx, "V/I", "f")
	_, _ = m.ResolveSecret(ctx, "V/I", "f")
	if n != 1 {
		t.Fatalf("expected single underlying call, got %d", n)
	}
}

func TestResolveSecret_Errors(t *testing.T) {
	ctx := context.Background()
	m := NewManager(time.Minute)
	m.runOp = func(_ context.Context, _ ...string) ([]byte, error) {
		return nil, nil
	}
	if _, err := m.ResolveSecret(ctx, "", ""); err == nil {
		t.Fatal("expected error for empty ref")
	}
	if _, err := m.ResolveSecret(ctx, "noSlash", ""); err == nil {
		t.Fatal("expected error for missing slash")
	}
}
