package server

import (
	"context"
	"desktopsecrets/internal/config"
	"desktopsecrets/internal/shm"
	"desktopsecrets/internal/utils"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func RunDaemon() {
	config.InitConfig()

	// Single instance guard for the daemon only.
	if err := utils.EnsureSingleInstance("desktop-secrets.lock"); err != nil {
		log.Fatalf("Another instance appears to be running: %v", err)
	}
	defer utils.ReleaseSingleInstance()

	// Handle graceful shutdown (Ctrl+C / SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := NewAppState()

	// Load alias mapping (required for KeePass resolution).
	if err := app.KP.LoadAliases(); err != nil {
		log.Printf("Failed to load aliases: %v", err)
	}

	token, err := utils.RandomTokenHex(32)
	if err != nil {
		log.Fatalf("failed to generate token: %v", err)
	}

	ds, err := NewDaemonServer(app, token)
	if err != nil {
		log.Fatalf("failed to create daemon server: %v", err)
	}
	app.Server = ds
	port := ds.Port

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- app.Server.Serve() // blocking call until shutdown
	}()

	// Publish daemon state to shared memory and keep mapping open.
	st := &shm.DaemonState{Port: port, Token: token, PID: os.Getpid()}
	buf, _ := json.Marshal(st)
	shmCleanup, err := shm.ShmDaemonPublish(buf)
	if err != nil {
		// If shm fails, you could fallback to a file (omitted here).
		log.Printf("shared memory publish failed (client discovery may not work): %v", err)
	}
	if shmCleanup != nil {
		defer shmCleanup() // keep open for process lifetime
	}

	// Shutdown on signals as well (tray Exit also shuts the server).
	go func() {
		select {
		case <-ctx.Done():
			// OS signal -> shut down server & quit tray if running.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if app.Server != nil {
				_ = app.Server.Shutdown(shutdownCtx)
			}
			// If tray is running, ask it to quit.
			// (If systray hasn't started yet, this is a no-op until it does.)
			// Import in tray.go handles systray.Quit() on Exit click; here we also try to close it.
			// We don't import systray in main to keep boundaries clear.
		case err := <-serverErrCh:
			// Server exited unexpectedly; log and continue to let tray exit path close app.
			if err != nil {
				log.Printf("server stopped with error: %v", err)
			} else {
				log.Printf("server stopped")
			}
		}
	}()

	// Start tray and block until Exit is clicked (or server exits and tray quits).
	RunTray(app)
}
