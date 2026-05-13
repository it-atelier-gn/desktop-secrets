package server

import (
	"context"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/approval"
	"github.com/it-atelier-gn/desktop-secrets/internal/audit"
	"github.com/it-atelier-gn/desktop-secrets/internal/aws"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
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
	EvictVault(key string)
	IsVaultUnlocked(key string) bool
}

type UserResolver interface {
	SetUnlockTTL(unlockTTL *utils.AtomicDuration)
	ResolvePassword(ctx context.Context, title string, ttl time.Duration) (string, error)
	Evict(title string)
	HasCached(title string) bool
}

type WincredResolver interface {
	Resolve(ctx context.Context, target, field string) (string, error)
}

type AWSResolver interface {
	ResolveSecret(ctx context.Context, secretID, field string) (string, error)
	ResolveParameter(ctx context.Context, name, field string) (string, error)
	Evict(key string)
}

type AzureResolver interface {
	ResolveSecret(ctx context.Context, ref, field string) (string, error)
	Evict(key string)
}

type GCPResolver interface {
	ResolveSecret(ctx context.Context, ref, field string) (string, error)
	Evict(key string)
}

type KeychainResolver interface {
	Resolve(ctx context.Context, service, account string) (string, error)
}

type VaultResolver interface {
	ResolveSecret(ctx context.Context, path, field string) (string, error)
	Evict(key string)
}

type OnePasswordResolver interface {
	ResolveSecret(ctx context.Context, ref, field string) (string, error)
	Evict(key string)
}

type AppState struct {
	KP                KPResolver
	USER              UserResolver
	WINCRED           WincredResolver
	AWS               AWSResolver
	AZKV              AzureResolver
	GCPSM             GCPResolver
	KEYCHAIN          KeychainResolver
	VAULT             VaultResolver
	ONEPASSWORD       OnePasswordResolver
	UnlockTTL           utils.AtomicDuration
	ShouldExit          utils.AtomicBool
	RetrievalApproval   utils.AtomicBool
	AutoApproveOnUnlock utils.AtomicBool
	Approvals           *approval.Store
	Gate                *approval.Gate
	Audit               *audit.Logger

	Server *DaemonServer
}

func NewAppState() *AppState {
	ttl := time.Duration(viper.GetInt("ttl")) * time.Minute
	store := approval.NewStore()
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
		Approvals:   store,
		Gate: approval.NewGateWithVerifier(store, nil,
			func(reason string) (osauth.Factor, error) { return osauth.Verify(reason) },
			func() string { return viper.GetString("approval_factor_required") },
		),
	}
	a.UnlockTTL.Store(ttl)
	a.RetrievalApproval.Store(viper.GetBool("retrieval_approval"))
	a.AutoApproveOnUnlock.Store(viper.GetBool("auto_approve_on_unlock"))

	a.USER.SetUnlockTTL(&a.UnlockTTL)
	a.KP.SetUnlockTTL(&a.UnlockTTL)

	if dir, err := utils.GetSettingsDirectory(); err == nil {
		if l, err := audit.New(dir); err == nil {
			a.Audit = l
		}
	}

	return a
}
