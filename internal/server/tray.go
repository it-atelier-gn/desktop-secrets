package server

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/assets"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
	"github.com/it-atelier-gn/desktop-secrets/internal/version"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/getlantern/systray"
	"github.com/spf13/viper"
)

func RunTray(app *AppState) {
	systray.Run(func() {
		if len(assets.IconBytes) > 0 {
			systray.SetIcon(assets.IconBytes)
		}
		systray.SetTitle("DesktopSecrets")
		systray.SetTooltip("Resolver for .env templates")

		settingsMenu := systray.AddMenuItem("Settings", "")
		ttlMenu := settingsMenu.AddSubMenuItem("Default Unlock TTL", "")
		ttlItems := make([]*systray.MenuItem, len(static.TTLOptions))
		for i, opt := range static.TTLOptions {
			ttlItems[i] = ttlMenu.AddSubMenuItemCheckbox(opt.Label, "", opt.IsDefault)
		}

		// Initialize selected TTL option from config
		configuredTTL := viper.GetInt("ttl")
		for i, opt := range static.TTLOptions {
			if opt.Minutes == configuredTTL {
				ttlItems[i].Check()
			} else {
				ttlItems[i].Uncheck()
			}
		}

		approvalItem := settingsMenu.AddSubMenuItemCheckbox(
			"Require retrieval approval",
			"Prompt before resolving a secret for a new client process",
			app.RetrievalApproval.Load(),
		)
		forgetItem := settingsMenu.AddSubMenuItem(
			"Forget all approvals",
			"Revoke every active retrieval-approval grant",
		)

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
				case <-approvalItem.ClickedCh:
					newVal := !app.RetrievalApproval.Load()
					viper.Set("retrieval_approval", newVal)
					if err := viper.WriteConfig(); err != nil {
						log.Printf("Failed to save retrieval_approval setting")
						continue
					}
					app.RetrievalApproval.Store(newVal)
					if newVal {
						approvalItem.Check()
					} else {
						approvalItem.Uncheck()
					}

				case <-forgetItem.ClickedCh:
					if app.Approvals != nil {
						app.Approvals.RevokeAll()
					}

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
					opt := static.TTLOptions[i]
					viper.Set("ttl", opt.Minutes)
					if err := viper.WriteConfig(); err != nil {
						log.Printf("Failed to save Default Unlock TTL setting")
						continue // Don't update UI on failure
					}

					// Only update on success
					app.UnlockTTL.Store(time.Duration(opt.Minutes) * time.Minute)
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
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("About")
		icon := fyne.NewStaticResource("icon.ico", assets.IconBytes)
		w.SetIcon(icon)
		w.Resize(fyne.NewSize(440, 250))

		version := widget.NewLabel(fmt.Sprintf("Version %s (%s)", version.Version, version.Revision))

		const repoURL = "https://github.com/it-atelier-gn/desktop-secrets"
		link := widget.NewHyperlink(repoURL, mustParseURL(repoURL))

		copyright := widget.NewLabel("© 2026 DesktopSecrets Contributors")

		content := container.NewVBox(
			version,
			link,
			copyright,
			widget.NewLabel(""))

		d := dialog.NewCustom("About DesktopSecrets", "OK", content, w)

		d.SetOnClosed(func() {
			w.Close()
		})

		w.Show()
		d.Show()
	})
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}
