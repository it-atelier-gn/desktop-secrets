package gcpsm

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type fakeSMClient struct {
	calls    int
	payload  string
	respErr  error
}

func (f *fakeSMClient) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...any) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.calls++
	if f.respErr != nil {
		return nil, f.respErr
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte(f.payload)},
	}, nil
}

func (f *fakeSMClient) Close() error { return nil }

func newManagerWithFake(ttl time.Duration, fc *fakeSMClient) *Manager {
	m := NewManager(ttl)
	m.cli = fc
	return m
}

func TestResolveSecretRoundTrip(t *testing.T) {
	fc := &fakeSMClient{payload: `{"username":"u","password":"p"}`}
	m := newManagerWithFake(time.Hour, fc)

	got, err := m.ResolveSecret(context.Background(), "proj/secret", "password")
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if got != "p" {
		t.Fatalf("got %q want %q", got, "p")
	}
}

func TestResolveSecretCachesAcrossCalls(t *testing.T) {
	fc := &fakeSMClient{payload: "raw-value"}
	m := newManagerWithFake(time.Hour, fc)

	for i := 0; i < 3; i++ {
		if _, err := m.ResolveSecret(context.Background(), "proj/sec", ""); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if fc.calls != 1 {
		t.Fatalf("expected 1 underlying call, got %d", fc.calls)
	}
}

func TestExpiredEntryEvictedOnRead(t *testing.T) {
	fc := &fakeSMClient{payload: "v"}
	m := newManagerWithFake(time.Millisecond, fc)
	if _, err := m.ResolveSecret(context.Background(), "proj/sec", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := m.ResolveSecret(context.Background(), "proj/sec", ""); err != nil {
		t.Fatal(err)
	}
	if fc.calls != 2 {
		t.Fatalf("expected 2 calls after expiry, got %d", fc.calls)
	}
}
