package server

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/buildmode"
	"github.com/it-atelier-gn/desktop-secrets/internal/config"
	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
	"github.com/it-atelier-gn/desktop-secrets/internal/shm"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
	"github.com/it-atelier-gn/desktop-secrets/internal/version"
	"github.com/it-atelier-gn/desktop-secrets/internal/winenv"

	"fyne.io/fyne/v2/app"
)

func RunDaemon() {
	memprotect.DisableErrorReporting()

	if dir, err := utils.GetSettingsDirectory(); err == nil {
		if f := setupDaemonLog(dir); f != nil {
			defer f.Close()
		}
	}
	log.Printf("daemon starting: pid=%d version=%s (%s)", os.Getpid(), version.Version, version.Revision)

	if loaded := winenv.Hydrate(); len(loaded) > 0 {
		log.Printf("env: hydrated %d variable(s) from the Windows registry", len(loaded))
	}

	if err := config.InitConfig(); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	if buildmode.Hardened {
		if err := ensureHardenedEnrollment(); err != nil {
			log.Fatalf("hardened build refuses to start: %v", err)
		}
	} else {
		if exists, _ := policy.MarkerExists(); exists {
			log.Fatalf("hardened-build marker present on this machine. Refusing to start the lite build. To intentionally downgrade run `getsec --allow-downgrade` once.")
		}
	}

	if store, err := policy.DefaultStore(); err == nil {
		outcome, applied, err := policy.Reconcile(store, func(reason string) (osauth.Factor, error) {
			return osauth.Verify(reason)
		})
		switch {
		case err == policy.ErrDowngradeRejected:
			log.Printf("policy: on-disk downgrade rejected; reverted to keystore policy %+v", applied)
		case err != nil:
			log.Printf("policy: reconcile failed: %v", err)
		default:
			log.Printf("policy: reconcile outcome=%d applied=%+v", outcome, applied)
		}
	} else {
		log.Printf("policy: keystore unavailable, skipping reconcile: %v", err)
	}

	if err := utils.EnsureSingleInstance("desktop-secrets.lock"); err != nil {
		log.Fatalf("Another instance appears to be running: %v", err)
	}
	defer utils.ReleaseSingleInstance()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	appState := NewAppState()

	if err := appState.KP.LoadAliases(); err != nil {
		log.Printf("Failed to load aliases: %v", err)
	}

	if err := appState.KP.LoadKeyfiles(); err != nil {
		log.Printf("Failed to load keyfiles: %v", err)
	}

	token, err := utils.RandomTokenHex(32)
	if err != nil {
		log.Fatalf("failed to generate token: %v", err)
	}

	ds, err := NewDaemonServer(appState, token)
	if err != nil {
		log.Fatalf("failed to create daemon server: %v", err)
	}
	appState.Server = ds
	endpoint := ds.Endpoint

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- appState.Server.Serve() // blocking call until shutdown
	}()

	st := &shm.DaemonState{Endpoint: endpoint, Token: token, PID: os.Getpid()}
	buf, _ := json.Marshal(st)
	shmCleanup, err := shm.ShmDaemonPublish(buf)
	if err != nil {
		log.Printf("shared memory publish failed (client discovery may not work): %v", err)
	}
	if shmCleanup != nil {
		defer shmCleanup() // keep open for process lifetime
	}

	go func() {
		select {
		case <-ctx.Done():
			log.Printf("daemon exiting: received shutdown signal")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if appState.Server != nil {
				_ = appState.Server.Shutdown(shutdownCtx)
			}
		case err := <-serverErrCh:
			if err != nil {
				log.Printf("server stopped with error: %v", err)
			} else {
				log.Printf("server stopped")
			}
		}
	}()

	go func() {
		runtime.LockOSThread()
		RunTray(appState)
		log.Printf("daemon exiting: tray loop ended (exit requested: %v)", appState.ShouldExit.Load())
		os.Exit(0)
	}()

	app := app.NewWithID("desktopsecrets")
	hiddenWindow := app.NewWindow("Daemon")
	hiddenWindow.SetCloseIntercept(func() {})
	hiddenWindow.Hide()
	app.Run()
	log.Printf("daemon exiting: UI loop ended")
}
