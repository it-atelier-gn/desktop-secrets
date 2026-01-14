package server

import (
	"context"
	"desktopsecrets/assets"
	"desktopsecrets/internal/version"
	_ "embed"
	"fmt"
	"time"

	"github.com/getlantern/systray"
	"github.com/ncruces/zenity"
	"github.com/spf13/viper"
)

type ttlOption struct {
	label     string
	minutes   int
	isDefault bool
}

var ttlOptions = []ttlOption{
	{label: "5 minutes", minutes: 5, isDefault: false},
	{label: "15 minutes (default)", minutes: 15, isDefault: true},
	{label: "1 hour", minutes: 60, isDefault: false},
	{label: "2 hours", minutes: 120, isDefault: false},
	{label: "4 hours", minutes: 240, isDefault: false},
}

func RunTray(app *AppState) {
	systray.Run(func() {
		if len(assets.IconBytes) > 0 {
			systray.SetIcon(assets.IconBytes)
		}
		systray.SetTitle("DesktopSecrets")
		systray.SetTooltip("Resolver for .env templates")

		settingsMenu := systray.AddMenuItem("Settings", "")
		ttlMenu := settingsMenu.AddSubMenuItem("Unlock TTL", "")
		ttlItems := make([]*systray.MenuItem, len(ttlOptions))
		for i, opt := range ttlOptions {
			ttlItems[i] = ttlMenu.AddSubMenuItemCheckbox(opt.label, "", opt.isDefault)
		}

		// Initialize selected TTL option from config
		configuredTTL := viper.GetInt("ttl")
		for i, opt := range ttlOptions {
			if opt.minutes == configuredTTL {
				ttlItems[i].Check()
			} else {
				ttlItems[i].Uncheck()
			}
		}

		systray.AddSeparator()
		about := systray.AddMenuItem("About", "")

		exit := systray.AddMenuItem("Exit", "Quit application")

		// Channel to receive TTL selection index from goroutines
		ttlSelectedCh := make(chan int)

		// Spawn goroutine for each TTL option to forward clicks to main loop
		for i := range ttlItems {
			go func(index int, item *systray.MenuItem) {
				for range item.ClickedCh {
					ttlSelectedCh <- index
				}
			}(i, ttlItems[i])
		}

		go func() {
			for {
				select {
				case <-exit.ClickedCh:
					app.ShouldExit.Store(true)

					// Graceful server shutdown.
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					if app.Server != nil {
						_ = app.Server.Shutdown(ctx)
					}
					cancel()

					// Quit the tray loop; main will unwind defers (including shm cleanup).
					systray.Quit()
					return

				case <-about.ClickedCh:
					showAboutDialog()

				case i := <-ttlSelectedCh:
					opt := ttlOptions[i]
					viper.Set("ttl", opt.minutes)
					if err := viper.WriteConfig(); err != nil {
						zenity.Error(
							"Failed to save TTL setting",
							zenity.Title("DesktopSecrets Config Error"),
						)
						continue // Don't update UI on failure
					}

					// Only update on success
					app.UnlockTTL.Store(time.Duration(opt.minutes) * time.Minute)
					for j := range ttlItems {
						if i == j {
							ttlItems[j].Check()
						} else {
							ttlItems[j].Uncheck()
						}
					}
				}
			}
		}()
	}, func() {
		// onExit: nothing else — shared-memory cleanup happens in main.go.
	})
}

func showAboutDialog() {
	message := fmt.Sprintf(
		"DesktopSecrets\n\n"+
			"Version: %s\n"+
			"Revision: %s\n\n"+
			"© 2026 DesktopSecrets Contributors\n\n"+
			"🔗 https://github.com/it-atelier-gn/desktop-secrets",
		version.Version, version.Revision,
	)

	zenity.Info(
		message,
		zenity.Title("About DesktopSecrets"),
		zenity.Width(400),
		zenity.Height(250),
	)
}
