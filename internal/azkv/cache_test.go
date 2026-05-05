package azkv

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type fakeVaultClient struct {
	calls int
	value string
	err   error
}

func (f *fakeVaultClient) GetSecret(_ context.Context, _ string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.calls++
	if f.err != nil {
		return azsecrets.GetSecretResponse{}, f.err
	}
	v := f.value
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: &v}}, nil
}

func newManagerWithFake(ttl time.Duration, fc *fakeVaultClient) *Manager {
	m := NewManager(ttl)
	m.newClient = func(_ string, _ *azidentity.DefaultAzureCredential) (vaultClient, error) {
		return fc, nil
	}
	// avoid hitting Azure auth during test
	m.cred = &azidentity.DefaultAzureCredential{}
	return m
}

func TestResolveSecretRoundTrip(t *testing.T) {
	fc := &fakeVaultClient{value: `{"username":"u","password":"p"}`}
	m := newManagerWithFake(time.Hour, fc)

	got, err := m.ResolveSecret(context.Background(), "myvault/dbpass", "password")
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if got != "p" {
		t.Fatalf("got %q want %q", got, "p")
	}
}

func TestResolveSecretCachesAcrossCalls(t *testing.T) {
	fc := &fakeVaultClient{value: "raw"}
	m := newManagerWithFake(time.Hour, fc)

	for i := 0; i < 3; i++ {
		if _, err := m.ResolveSecret(context.Background(), "myvault/k", ""); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if fc.calls != 1 {
		t.Fatalf("expected 1 underlying call, got %d", fc.calls)
	}
}

func TestExpiredEntryEvictedOnRead(t *testing.T) {
	fc := &fakeVaultClient{value: "v"}
	m := newManagerWithFake(time.Millisecond, fc)
	if _, err := m.ResolveSecret(context.Background(), "myvault/k", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := m.ResolveSecret(context.Background(), "myvault/k", ""); err != nil {
		t.Fatal(err)
	}
	if fc.calls != 2 {
		t.Fatalf("expected 2 calls after expiry, got %d", fc.calls)
	}
}
