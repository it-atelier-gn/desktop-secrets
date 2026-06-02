package server

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/assets"
	"github.com/it-atelier-gn/desktop-secrets/internal/cacheinfo"
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
		aliases := systray.AddMenuItem("Aliases…", "Configure KeePass database aliases")
		keyfiles := systray.AddMenuItem("Keyfiles…", "Configure KeePass keyfile associations")
		cached := systray.AddMenuItem("Cached secrets…", "View and forget cached secrets")
		systray.AddSeparator()
		about := systray.AddMenuItem("About", "")
		exit := systray.AddMenuItem("Exit", "Quit application")

		go func() {
			for {
				select {
				case <-settings.ClickedCh:
					showSettingsWindow(app)

				case <-aliases.ClickedCh:
					showAliasesWindow(app)

				case <-keyfiles.ClickedCh:
					showKeyfilesWindow(app)

				case <-cached.ClickedCh:
					showCachedSecretsWindow(app)

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

type cachedItem struct {
	key     string
	detail  string
	expires time.Time
	evict   func()
}

type cachedGroup struct {
	name     string
	items    []cachedItem
	evictAll func()
}

func (app *AppState) cachedGroups() []cachedGroup {
	groups := []cachedGroup{
		{name: "KeePass", evictAll: app.KP.EvictAll},
		{name: "AWS", evictAll: app.AWS.EvictAll},
		{name: "Azure Key Vault", evictAll: app.AZKV.EvictAll},
		{name: "GCP Secret Manager", evictAll: app.GCPSM.EvictAll},
		{name: "HashiCorp Vault", evictAll: app.VAULT.EvictAll},
		{name: "1Password", evictAll: app.ONEPASSWORD.EvictAll},
		{name: "Prompt", evictAll: app.USER.EvictAll},
	}

	for _, cv := range app.KP.CachedVaults() {
		key := cv.Key
		groups[0].items = append(groups[0].items, cachedItem{
			key: cv.Key, detail: cv.Filename, expires: cv.Expires,
			evict: func() { app.KP.EvictVault(key) },
		})
	}

	add := func(i int, evict func(string), entries []cacheinfo.Entry) {
		for _, e := range entries {
			key := e.Key
			groups[i].items = append(groups[i].items, cachedItem{
				key: e.Key, expires: e.Expires,
				evict: func() { evict(key) },
			})
		}
	}
	add(1, app.AWS.Evict, app.AWS.CachedKeys())
	add(2, app.AZKV.Evict, app.AZKV.CachedKeys())
	add(3, app.GCPSM.Evict, app.GCPSM.CachedKeys())
	add(4, app.VAULT.Evict, app.VAULT.CachedKeys())
	add(5, app.ONEPASSWORD.Evict, app.ONEPASSWORD.CachedKeys())
	add(6, app.USER.Evict, app.USER.CachedKeys())

	return groups
}

func showCachedSecretsWindow(app *AppState) {
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("Cached Secrets")
		w.SetIcon(fyne.NewStaticResource("icon.ico", assets.IconBytes))
		w.Resize(fyne.NewSize(560, 460))

		body := container.NewVBox()

		var refresh func()
		refresh = func() {
			body.RemoveAll()
			var total int
			for _, g := range app.cachedGroups() {
				if len(g.items) == 0 {
					continue
				}
				total += len(g.items)
				forgetGroup := widget.NewButton("Forget all", func() {
					g.evictAll()
					refresh()
				})
				header := container.NewBorder(nil, nil,
					widget.NewLabelWithStyle(g.name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
					forgetGroup, nil)
				body.Add(header)
				for _, it := range g.items {
					evict := it.evict
					text := it.key
					if it.detail != "" {
						text += "\n" + it.detail
					}
					text += fmt.Sprintf("\nexpires in %s", time.Until(it.expires).Round(time.Second))
					info := widget.NewLabel(text)
					info.Wrapping = fyne.TextWrapWord
					forget := widget.NewButton("Forget", func() {
						evict()
						refresh()
					})
					body.Add(container.NewBorder(nil, nil, nil, forget, info))
				}
				body.Add(widget.NewSeparator())
			}
			if total == 0 {
				body.Add(widget.NewLabel("No cached secrets."))
			}
			body.Refresh()
		}
		refresh()

		forgetAll := widget.NewButton("Forget All", func() {
			for _, g := range app.cachedGroups() {
				g.evictAll()
			}
			refresh()
		})
		refreshBtn := widget.NewButton("Refresh", refresh)
		top := container.NewHBox(forgetAll, refreshBtn)

		content := container.NewBorder(top, nil, nil, nil, container.NewVScroll(body))
		w.SetContent(content)
		w.Show()
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
