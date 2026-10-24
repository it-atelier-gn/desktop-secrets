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

	"github.com/it-atelier-gn/desktop-secrets/internal/config"
	"github.com/it-atelier-gn/desktop-secrets/internal/memprotect"
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
	if err := memprotect.HardenProcess(); err != nil {
		log.Printf("warning: process memory stays readable for other processes: %v", err)
	}
	if err := memprotect.Init(); err != nil {
		log.Printf("warning: memory protection incomplete: %v", err)
	}
	if failures := os.Getenv(utils.StartFailuresEnv); failures != "" {
		log.Printf("warning: earlier start attempts failed: %s", failures)
		_ = os.Unsetenv(utils.StartFailuresEnv)
	}
	if status := utils.JobStatus(); status != "" {
		log.Print(status)
	}
	if utils.JobKillsOnClose() {
		log.Print("warning: the daemon runs inside a kill-on-close job object; it stops when the process that started it ends, so unlocked vaults are forgotten before their TTL expires")
	}

	if loaded := winenv.Hydrate(); len(loaded) > 0 {
		log.Printf("env: hydrated %d variable(s) from the Windows registry", len(loaded))
	}

	if err := config.InitConfig(); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	if err := utils.EnsureSingleInstance("desktop-secrets.lock"); err != nil {
		log.Fatalf("Another instance appears to be running: %v", err)
	}
	defer utils.ReleaseSingleInstance()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	appState := NewAppState()
	if floor := appState.Floor(); floor != (policy.Floor{}) {
		log.Printf("policy: minimum settings from %s: %+v", policy.Location, floor)
		if floor.IgnoredFactor() {
			log.Printf("policy: minimum approval factor %s is not available on this platform and is ignored", floor.MinApprovalFactor)
		}
	}

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
		serverErrCh <- appState.Server.Serve()
	}()

	st := &shm.DaemonState{Endpoint: endpoint, Token: token, PID: os.Getpid()}
	buf, _ := json.Marshal(st)
	shmCleanup, err := shm.ShmDaemonPublish(buf)
	if err != nil {
		log.Printf("shared memory publish failed (client discovery may not work): %v", err)
	}
	if shmCleanup != nil {
		defer shmCleanup()
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
