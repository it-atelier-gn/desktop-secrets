package server

import (
	"context"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/keepass"
	"github.com/it-atelier-gn/desktop-secrets/internal/user"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"

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

type AppState struct {
	KP         KPResolver
	USER       UserResolver
	UnlockTTL  utils.AtomicDuration
	ShouldExit utils.AtomicBool

	Server *DaemonServer
}

func NewAppState() *AppState {
	a := &AppState{
		KP:        keepass.NewKPManager(),
		USER:      user.NewUserManager(),
		UnlockTTL: utils.AtomicDuration{},
	}
	a.UnlockTTL.Store(time.Duration(viper.GetInt("ttl")) * time.Minute)

	a.USER.SetUnlockTTL(&a.UnlockTTL)
	a.KP.SetUnlockTTL(&a.UnlockTTL)

	return a
}
