package vault

import (
	"context"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

type fakeLogical struct {
	calls int
	resp  *vaultapi.Secret
	err   error
}

func (f *fakeLogical) ReadWithContext(_ context.Context, _ string) (*vaultapi.Secret, error) {
	f.calls++
	return f.resp, f.err
}

func newManagerWithFake(ttl time.Duration, fl *fakeLogical) *Manager {
	m := NewManager(ttl)
	m.logical = fl
	return m
}

func TestResolveSecretRoundTrip(t *testing.T) {
	fl := &fakeLogical{
		resp: &vaultapi.Secret{Data: map[string]interface{}{
			"data": map[string]interface{}{"password": "super-secret", "username": "alice"},
		}},
	}
	m := newManagerWithFake(time.Hour, fl)

	got, err := m.ResolveSecret(context.Background(), "secret/data/myapp", "password")
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if got != "super-secret" {
		t.Fatalf("got %q want %q", got, "super-secret")
	}
}

func TestResolveSecretCachesAcrossCalls(t *testing.T) {
	fl := &fakeLogical{
		resp: &vaultapi.Secret{Data: map[string]interface{}{
			"data": map[string]interface{}{"password": "p"},
		}},
	}
	m := newManagerWithFake(time.Hour, fl)

	for i := 0; i < 3; i++ {
		if _, err := m.ResolveSecret(context.Background(), "secret/data/x", "password"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if fl.calls != 1 {
		t.Fatalf("expected 1 underlying call, got %d", fl.calls)
	}
}

func TestExpiredEntryEvictedOnRead(t *testing.T) {
	fl := &fakeLogical{
		resp: &vaultapi.Secret{Data: map[string]interface{}{
			"data": map[string]interface{}{"password": "p"},
		}},
	}
	m := newManagerWithFake(time.Millisecond, fl)
	if _, err := m.ResolveSecret(context.Background(), "secret/data/x", "password"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := m.ResolveSecret(context.Background(), "secret/data/x", "password"); err != nil {
		t.Fatal(err)
	}
	if fl.calls != 2 {
		t.Fatalf("expected 2 calls after expiry, got %d", fl.calls)
	}
}

