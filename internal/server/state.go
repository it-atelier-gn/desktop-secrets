package server

import (
	"context"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/aws"
	"github.com/it-atelier-gn/desktop-secrets/internal/azkv"
	"github.com/it-atelier-gn/desktop-secrets/internal/gcpsm"
	"github.com/it-atelier-gn/desktop-secrets/internal/keepass"
	"github.com/it-atelier-gn/desktop-secrets/internal/keychain"
	"github.com/it-atelier-gn/desktop-secrets/internal/onepassword"
	"github.com/it-atelier-gn/desktop-secrets/internal/user"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
	"github.com/it-atelier-gn/desktop-secrets/internal/vault"
	"github.com/it-atelier-gn/desktop-secrets/internal/wincred"

	"github.com/spf13/viper"
)

type KPResolver interface {
	SetUnlockTTL(unlockTTL *utils.AtomicDuration)
	LoadAliases() error
	LoadKeyfiles() error
	ResolvePassword(ctx context.Context, vault, title string, master string, ttl time.Duration, resolve func(expr string) (string, error)) (string, error)
}

type UserResolver interface {
	SetUnlockTTL(unlockTTL *utils.AtomicDuration)
	ResolvePassword(ctx context.Context, title string, ttl time.Duration) (string, error)
}

type WincredResolver interface {
	Resolve(ctx context.Context, target, field string) (string, error)
}

type AWSResolver interface {
	ResolveSecret(ctx context.Context, secretID, field string) (string, error)
	ResolveParameter(ctx context.Context, name, field string) (string, error)
}

type AzureResolver interface {
	ResolveSecret(ctx context.Context, ref, field string) (string, error)
}

type GCPResolver interface {
	ResolveSecret(ctx context.Context, ref, field string) (string, error)
}

type KeychainResolver interface {
	Resolve(ctx context.Context, service, account string) (string, error)
}

type VaultResolver interface {
	ResolveSecret(ctx context.Context, path, field string) (string, error)
}

type OnePasswordResolver interface {
	ResolveSecret(ctx context.Context, ref, field string) (string, error)
}

type AppState struct {
	KP          KPResolver
	USER        UserResolver
	WINCRED     WincredResolver
	AWS         AWSResolver
	AZKV        AzureResolver
	GCPSM       GCPResolver
	KEYCHAIN    KeychainResolver
	VAULT       VaultResolver
	ONEPASSWORD OnePasswordResolver
	UnlockTTL   utils.AtomicDuration
	ShouldExit  utils.AtomicBool

	Server *DaemonServer
}

func NewAppState() *AppState {
	ttl := time.Duration(viper.GetInt("ttl")) * time.Minute
	a := &AppState{
		KP:          keepass.NewKPManager(),
		USER:        user.NewUserManager(),
		WINCRED:     wincred.NewManager(),
		AWS:         aws.NewManager(ttl),
		AZKV:        azkv.NewManager(ttl),
		GCPSM:       gcpsm.NewManager(ttl),
		KEYCHAIN:    keychain.NewManager(),
		VAULT:       vault.NewManager(ttl),
		ONEPASSWORD: onepassword.NewManager(ttl),
		UnlockTTL:   utils.AtomicDuration{},
	}
	a.UnlockTTL.Store(ttl)

	a.USER.SetUnlockTTL(&a.UnlockTTL)
	a.KP.SetUnlockTTL(&a.UnlockTTL)

	return a
}
