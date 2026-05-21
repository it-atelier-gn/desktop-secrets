package server

import (
	"log"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/spf13/viper"

	"github.com/it-atelier-gn/desktop-secrets/assets"
	"github.com/it-atelier-gn/desktop-secrets/internal/buildmode"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

func showSettingsWindow(app *AppState) {
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("DesktopSecrets — Settings")
		w.SetIcon(fyne.NewStaticResource("icon.ico", assetsIconBytes()))
		w.Resize(fyne.NewSize(640, 620))

		header := widget.NewLabelWithStyle(
			"Retrieval approval",
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)

		var intro *widget.Label
		if buildmode.Hardened {
			intro = widget.NewLabel(
				"This is the hardened build. Every retrieval requires Windows Hello " +
					"or a hardware security key. The approval mode cannot be lowered " +
					"from the UI — install the lite build if you want the weaker modes.",
			)
		} else {
			intro = widget.NewLabel(
				"Choose how the daemon decides whether to release a secret to a " +
					"requesting process. Stronger options ask for more proof; weaker " +
					"options are more convenient but trust every process that runs as " +
					"you. For agent-safe handling, install the hardened build.",
			)
		}
		intro.Wrapping = fyne.TextWrapWord

		helloAvail := osauth.CheckAvailability()
		helloOK := helloAvail == osauth.AvailabilityAvailable

		labels := make([]string, 0, len(static.ApprovalModeOptions))
		labelByMode := map[static.ApprovalMode]string{}
		modeByLabel := map[string]static.ApprovalMode{}
		for _, opt := range static.ApprovalModeOptions {
			label := opt.Label
			if opt.Mode == static.ApprovalModeAdvanced && !helloOK {
				label = opt.Label + " — unavailable"
			}
			labels = append(labels, label)
			labelByMode[opt.Mode] = label
			modeByLabel[label] = opt.Mode
		}

		current := static.DeriveApprovalMode(
			viper.GetBool("retrieval_approval"),
			viper.GetString("approval_factor_required"),
		)
		if _, ok := labelByMode[current]; !ok {
			current = static.ApprovalModeOff
			approval, factor := static.ApplyApprovalMode(current)
			viper.Set("retrieval_approval", approval)
			viper.Set("approval_factor_required", factor)
			if err := viper.WriteConfig(); err != nil {
				log.Printf("Failed to normalize approval mode to Off: %v", err)
			}
			app.RetrievalApproval.Store(approval)
			prompt.AutoAllowPending()
		}

		explain := widget.NewLabel("")
		explain.Wrapping = fyne.TextWrapWord
		setExplain := func(m static.ApprovalMode) {
			for _, opt := range static.ApprovalModeOptions {
				if opt.Mode == m {
					text := opt.Description
					if m == static.ApprovalModeAdvanced && !helloOK {
						text += "\n\nNot available right now: " + helloAvail.Reason() +
							". Configure a Windows Hello method (PIN, fingerprint or " +
							"face) under Settings → Accounts → Sign-in options and " +
							"reopen this dialog."
					}
					explain.SetText(text)
					return
				}
			}
			explain.SetText("")
		}

		var radio *widget.RadioGroup
		if !buildmode.Hardened {
			radio = widget.NewRadioGroup(labels, nil)
			radio.Required = true
			radio.SetSelected(labelByMode[current])
		}
		setExplain(current)

		onChanged := func(sel string) {
			picked, ok := modeByLabel[sel]
			if !ok {
				return
			}
			if picked == static.ApprovalModeAdvanced && !helloOK {
				radio.SetSelected(labelByMode[current])
				setExplain(current)
				showHelloUnavailableDialog(helloAvail)
				return
			}
			setExplain(picked)
			if picked == current {
				return
			}
			if picked == static.ApprovalModeAdvanced {
				if _, err := osauth.Verify(
					"Confirm Advanced retrieval approval (Windows Hello)",
				); err != nil {
					log.Printf("advanced approval not activated: %v", err)
					radio.SetSelected(labelByMode[current])
					setExplain(current)
					return
				}
			}
			prevApproval := viper.GetBool("retrieval_approval")
			prevFactor := viper.GetString("approval_factor_required")
			newApproval, newFactor := static.ApplyApprovalMode(picked)
			viper.Set("retrieval_approval", newApproval)
			viper.Set("approval_factor_required", newFactor)
			verifier := func() bool { return true }
			if helloOK {
				verifier = verifyWithHello("Confirm retrieval-approval change")
			}
			if !commitPolicyChange(verifier) {
				viper.Set("retrieval_approval", prevApproval)
				viper.Set("approval_factor_required", prevFactor)
				log.Printf("retrieval-approval mode change rejected by policy keystore")
				radio.SetSelected(labelByMode[current])
				setExplain(current)
				return
			}
			if err := viper.WriteConfig(); err != nil {
				viper.Set("retrieval_approval", prevApproval)
				viper.Set("approval_factor_required", prevFactor)
				log.Printf("Failed to save retrieval-approval mode: %v", err)
				radio.SetSelected(labelByMode[current])
				setExplain(current)
				return
			}
			app.RetrievalApproval.Store(newApproval)
			if !newApproval {
				prompt.AutoAllowPending()
			}
			current = picked
		}
		if radio != nil {
			radio.OnChanged = onChanged
		}

		ttlHeader := widget.NewLabelWithStyle(
			"Default unlock TTL",
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		ttlIntro := widget.NewLabel(
			"How long a vault stays unlocked after a successful password prompt. " +
				"Approval grants use the duration picked on the approval dialog and " +
				"are independent of this setting.",
		)
		ttlIntro.Wrapping = fyne.TextWrapWord

		ttlLabels := make([]string, 0, len(static.TTLOptions))
		ttlByLabel := map[string]int{}
		for _, opt := range static.TTLOptions {
			ttlLabels = append(ttlLabels, opt.Label)
			ttlByLabel[opt.Label] = opt.Minutes
		}
		ttlSelect := widget.NewSelect(ttlLabels, nil)
		configuredTTL := viper.GetInt("ttl")
		for _, opt := range static.TTLOptions {
			if opt.Minutes == configuredTTL {
				ttlSelect.SetSelected(opt.Label)
				break
			}
		}
		ttlSelect.OnChanged = func(sel string) {
			minutes, ok := ttlByLabel[sel]
			if !ok {
				return
			}
			prev := viper.GetInt("ttl")
			if minutes == prev {
				return
			}
			viper.Set("ttl", minutes)
			if err := viper.WriteConfig(); err != nil {
				viper.Set("ttl", prev)
				log.Printf("Failed to save default unlock TTL: %v", err)
				return
			}
			app.UnlockTTL.Store(time.Duration(minutes) * time.Minute)
		}

		closeBtn := widget.NewButton("Close", func() { w.Close() })

		items := []fyne.CanvasObject{header, intro}
		if radio != nil {
			items = append(items, radio)
		}
		items = append(items,
			explain,
			widget.NewSeparator(),
			ttlHeader,
			ttlIntro,
			ttlSelect,
			widget.NewSeparator(),
			container.NewHBox(closeBtn),
		)
		content := container.NewVBox(items...)

		w.SetContent(container.NewVScroll(content))
		w.Show()
	})
}

func assetsIconBytes() []byte {
	if len(assets.IconBytes) == 0 {
		return nil
	}
	return assets.IconBytes
}
