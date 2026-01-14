package server

import (
	"context"
	"desktopsecrets/internal/keepass"
	"desktopsecrets/internal/user"
	"desktopsecrets/internal/utils"
	"time"

	"github.com/spf13/viper"
)

type KPResolver interface {
	LoadAliases() error
	ResolvePassword(ctx context.Context, vault, title string, master string, ttl time.Duration) (string, error)
}

type UserResolver interface {
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
	return a
}
