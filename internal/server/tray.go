package server

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/assets"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
	"github.com/it-atelier-gn/desktop-secrets/internal/version"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/getlantern/systray"
)

func RunTray(app *AppState) {
	systray.Run(func() {
		if len(assets.IconBytes) > 0 {
			systray.SetIcon(assets.IconBytes)
		}
		systray.SetTitle("DesktopSecrets")
		systray.SetTooltip("Resolver for .env templates")

		settings := systray.AddMenuItem("Settings…", "Open the Settings window")
		systray.AddSeparator()
		about := systray.AddMenuItem("About", "")
		exit := systray.AddMenuItem("Exit", "Quit application")

		go func() {
			for {
				select {
				case <-settings.ClickedCh:
					showSettingsWindow(app)

				case <-about.ClickedCh:
					showAboutDialog()

				case <-exit.ClickedCh:
					app.ShouldExit.Store(true)

					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					if app.Server != nil {
						_ = app.Server.Shutdown(ctx)
					}
					cancel()

					systray.Quit()
					return
				}
			}
		}()
	}, func() {})
}

func showHelloUnavailableDialog(reason osauth.Availability) {
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("Windows Hello not available")
		w.SetIcon(fyne.NewStaticResource("icon.ico", assets.IconBytes))
		w.Resize(fyne.NewSize(520, 260))

		title := widget.NewLabelWithStyle(
			"Windows Hello can't be used yet",
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		why := widget.NewLabel("Reason: " + reason.Reason())
		why.Wrapping = fyne.TextWrapWord

		help := widget.NewLabel(
			"To enable OS authentication, open Windows Settings → Accounts → " +
				"Sign-in options and add a Windows Hello method: a PIN, a " +
				"fingerprint, or facial recognition. Any one is enough — pick " +
				"whatever your device supports. Then come back here and try " +
				"again.\n\n" +
				"Until a method is configured, the approval mode stays on " +
				"\"Standard\".",
		)
		help.Wrapping = fyne.TextWrapWord

		content := container.NewVBox(title, why, widget.NewSeparator(), help)
		d := dialog.NewCustom("Windows Hello not available", "OK", content, w)
		d.SetOnClosed(func() { w.Close() })
		w.Show()
		d.Show()
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

func commitPolicyChange(verifyWeaken func() bool) bool {
	store, err := policy.DefaultStore()
	if err != nil {
		log.Printf("policy: keystore unavailable: %v", err)
		return false
	}
	candidate := policy.FromViper()
	stored, err := store.Load()
	if err != nil {
		log.Printf("policy: keystore load failed: %v", err)
		return false
	}
	if stored == nil {
		return store.Save(candidate) == nil
	}
	switch policy.Compare(candidate, *stored) {
	case policy.RelEqual, policy.RelStricter:
		return store.Save(candidate) == nil
	case policy.RelWeaker, policy.RelMixed:
		if verifyWeaken == nil || !verifyWeaken() {
			return false
		}
		return store.Save(candidate) == nil
	}
	return false
}

func verifyWithHello(reason string) func() bool {
	return func() bool {
		_, err := osauth.Verify(reason)
		return err == nil
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}
