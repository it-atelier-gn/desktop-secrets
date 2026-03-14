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

	"fyne.io/fyne/v2/app"
)

func RunDaemon() {
	// Initialize configuration.
	if err := config.InitConfig(); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	// Single instance guard for the daemon only.
	if err := utils.EnsureSingleInstance("desktop-secrets.lock"); err != nil {
		log.Fatalf("Another instance appears to be running: %v", err)
	}
	defer utils.ReleaseSingleInstance()

	// Handle graceful shutdown (Ctrl+C / SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	appState := NewAppState()

	// Load alias mapping.
	if err := appState.KP.LoadAliases(); err != nil {
		log.Printf("Failed to load aliases: %v", err)
	}

	// Load keyfile mapping.
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
	port := ds.Port

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- appState.Server.Serve() // blocking call until shutdown
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
			if appState.Server != nil {
				_ = appState.Server.Shutdown(shutdownCtx)
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
	go func() {
		RunTray(appState)
		os.Exit(0)
	}()

	app := app.NewWithID("desktopsecrets")
	// Create a hidden window to prevent the app from exiting when dialogs close
	hiddenWindow := app.NewWindow("Daemon")
	hiddenWindow.SetCloseIntercept(func() {})
	hiddenWindow.Hide()
	app.Run()
}
