package server

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/spf13/viper"

	"github.com/it-atelier-gn/desktop-secrets/assets"
	"github.com/it-atelier-gn/desktop-secrets/internal/osauth"
	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"
)

const managedText = "This setting is managed by your organization."

func showSettingsWindow(app *AppState) {
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("DesktopSecrets — Settings")
		w.SetIcon(fyne.NewStaticResource("icon.ico", assetsIconBytes()))
		w.Resize(fyne.NewSize(640, 480))

		floor := app.Floor()

		header := widget.NewLabelWithStyle(
			"Retrieval approval",
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)

		intro := widget.NewLabel(
			"Choose how the daemon decides whether to release a secret to a " +
				"requesting process. Stronger options ask for more proof; weaker " +
				"options are more convenient but trust every process that runs as " +
				"you.",
		)
		intro.Wrapping = fyne.TextWrapWord

		helloAvail := osauth.CheckAvailability()
		helloOK := helloAvail == osauth.AvailabilityAvailable
		advancedOK := helloOK || securityKeyAvailable()

		labels := make([]string, 0, len(static.ApprovalModeOptions))
		labelByMode := map[static.ApprovalMode]string{}
		modeByLabel := map[string]static.ApprovalMode{}
		for _, opt := range static.ApprovalModeOptions {
			label := opt.Label
			switch {
			case !floor.AllowsMode(opt.Mode):
				label = opt.Label + " — managed by your organization"
			case opt.Mode == static.ApprovalModeAdvanced && !advancedOK:
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
		if !floor.AllowsMode(current) {
			current = floor.MinMode()
		}

		explain := widget.NewLabel("")
		explain.Wrapping = fyne.TextWrapWord
		setExplain := func(m static.ApprovalMode) {
			for _, opt := range static.ApprovalModeOptions {
				if opt.Mode == m {
					text := opt.Description
					if m == static.ApprovalModeAdvanced && !advancedOK {
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

		radio := widget.NewRadioGroup(labels, nil)
		radio.Required = true
		radio.SetSelected(labelByMode[current])
		setExplain(current)

		revert := func() {
			radio.SetSelected(labelByMode[current])
			setExplain(current)
		}

		radio.OnChanged = func(sel string) {
			picked, ok := modeByLabel[sel]
			if !ok {
				return
			}
			if !floor.AllowsMode(picked) {
				revert()
				dialog.ShowInformation("Managed setting", managedText, w)
				return
			}
			if picked == static.ApprovalModeAdvanced && !advancedOK {
				revert()
				showHelloUnavailableDialog(helloAvail)
				return
			}
			setExplain(picked)
			if picked == current {
				return
			}
			if picked == static.ApprovalModeAdvanced {
				var err error
				if helloOK {
					_, err = osauth.Verify("Confirm Advanced retrieval approval (Windows Hello)")
				} else {
					err = ensureSecurityKey()
				}
				if err != nil {
					log.Printf("advanced approval not activated: %v", err)
					revert()
					return
				}
			}
			prevApproval := viper.GetBool("retrieval_approval")
			prevFactor := viper.GetString("approval_factor_required")
			newApproval, newFactor := static.ApplyApprovalMode(picked)
			viper.Set("retrieval_approval", newApproval)
			viper.Set("approval_factor_required", newFactor)
			if err := viper.WriteConfig(); err != nil {
				viper.Set("retrieval_approval", prevApproval)
				viper.Set("approval_factor_required", prevFactor)
				log.Printf("Failed to save retrieval-approval mode: %v", err)
				revert()
				return
			}
			app.ApplySettings()
			if !app.RetrievalApproval.Load() {
				prompt.AutoAllowPending()
			}
			current = picked
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
		labelByTTL := map[int]string{}
		for _, opt := range static.TTLOptions {
			label := opt.Label
			if !floor.AllowsTTL(opt.Minutes) {
				label += " — managed by your organization"
			}
			ttlLabels = append(ttlLabels, label)
			ttlByLabel[label] = opt.Minutes
			labelByTTL[opt.Minutes] = label
		}
		ttlSelect := widget.NewSelect(ttlLabels, nil)
		currentTTL := floor.EffectiveTTL(viper.GetInt("ttl"))
		showTTL := func() {
			if label, ok := labelByTTL[currentTTL]; ok {
				ttlSelect.SetSelected(label)
			} else {
				ttlSelect.ClearSelected()
			}
		}
		showTTL()
		ttlSelect.OnChanged = func(sel string) {
			minutes, ok := ttlByLabel[sel]
			if !ok || minutes == currentTTL {
				return
			}
			if !floor.AllowsTTL(minutes) {
				showTTL()
				dialog.ShowInformation("Managed setting", managedText, w)
				return
			}
			prev := viper.GetInt("ttl")
			viper.Set("ttl", minutes)
			if err := viper.WriteConfig(); err != nil {
				viper.Set("ttl", prev)
				log.Printf("Failed to save default unlock TTL: %v", err)
				showTTL()
				return
			}
			app.ApplySettings()
			currentTTL = minutes
		}

		minHeader := widget.NewLabelWithStyle(
			"Minimum settings",
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		minIntro := widget.NewLabel(
			"An administrator can set minimum settings for every user of this " +
				"computer, through group policy or in " + policy.Location + ". " +
				"Changing them here asks for administrator rights.",
		)
		minIntro.Wrapping = fyne.TextWrapWord
		minState := widget.NewLabel(describeFloor(floor))
		minState.Wrapping = fyne.TextWrapWord
		minBtn := widget.NewButton("Change minimum settings…", func() {
			showFloorDialog(app, w)
		})

		closeBtn := widget.NewButton("Close", func() { w.Close() })

		content := container.NewVBox(
			header,
			intro,
			radio,
			explain,
			widget.NewSeparator(),
			ttlHeader,
			ttlIntro,
			ttlSelect,
			widget.NewSeparator(),
			minHeader,
			minIntro,
			minState,
			container.NewHBox(minBtn),
			widget.NewSeparator(),
			container.NewHBox(closeBtn),
		)

		w.SetContent(container.NewVScroll(content))
		w.Show()
	})
}

func describeFloor(f policy.Floor) string {
	if f == (policy.Floor{}) {
		return "No minimum settings are configured."
	}
	lines := []string{}
	if f.RetrievalApproval {
		lines = append(lines, "• Approval is required for every retrieval.")
	}
	if f.MinApprovalFactor == static.ApprovalFactorOSLocal {
		if policy.FactorEnforced {
			lines = append(lines, "• Every approval requires Windows Hello or a security key.")
		} else {
			lines = append(lines, "• Windows Hello or a security key is required, which this platform does not offer; the requirement is ignored.")
		}
	}
	if f.MaxUnlockTTL > 0 {
		lines = append(lines, fmt.Sprintf("• Vaults stay unlocked for at most %d minutes.", f.MaxUnlockTTL))
	}
	if len(lines) == 0 {
		return "No minimum settings are configured."
	}
	return strings.Join(lines, "\n")
}

func showFloorDialog(app *AppState, parent fyne.Window) {
	f := app.Floor()

	approvalCheck := widget.NewCheck("Require approval for every retrieval", nil)
	approvalCheck.SetChecked(f.RetrievalApproval)

	factorCheck := widget.NewCheck("Require Windows Hello or a security key for every approval", nil)
	factorCheck.SetChecked(f.MinApprovalFactor == static.ApprovalFactorOSLocal)

	const noLimit = "No limit"
	ttlLabels := []string{noLimit}
	ttlByLabel := map[string]int{noLimit: 0}
	selected := noLimit
	for _, opt := range static.TTLOptions {
		label := strings.TrimSuffix(opt.Label, " (default)")
		ttlLabels = append(ttlLabels, label)
		ttlByLabel[label] = opt.Minutes
		if opt.Minutes == f.MaxUnlockTTL {
			selected = label
		}
	}
	if selected == noLimit && f.MaxUnlockTTL > 0 {
		label := fmt.Sprintf("%d minutes", f.MaxUnlockTTL)
		ttlLabels = append(ttlLabels, label)
		ttlByLabel[label] = f.MaxUnlockTTL
		selected = label
	}
	ttlSelect := widget.NewSelect(ttlLabels, nil)
	ttlSelect.SetSelected(selected)

	items := []fyne.CanvasObject{approvalCheck}
	if policy.FactorEnforced {
		items = append(items, factorCheck)
	}
	items = append(items, widget.NewLabel("Maximum unlock TTL"), ttlSelect)

	dialog.ShowCustomConfirm("Minimum settings", "Apply", "Cancel", container.NewVBox(items...), func(ok bool) {
		if !ok {
			return
		}
		next := policy.Floor{
			RetrievalApproval: approvalCheck.Checked,
			MaxUnlockTTL:      ttlByLabel[ttlSelect.Selected],
		}
		if factorCheck.Checked {
			next.MinApprovalFactor = static.ApprovalFactorOSLocal
		}
		if next == f {
			return
		}
		go func() {
			err := policy.SaveElevated(next)
			fyne.Do(func() {
				switch {
				case errors.Is(err, policy.ErrElevationCanceled):
					return
				case err != nil:
					log.Printf("policy: minimum settings not saved: %v", err)
					dialog.ShowError(err, parent)
					return
				}
				log.Printf("policy: minimum settings changed to %+v", next)
				app.ApplySettings()
				if !app.RetrievalApproval.Load() {
					prompt.AutoAllowPending()
				}
				parent.Close()
				showSettingsWindow(app)
			})
		}()
	}, parent)
}

func assetsIconBytes() []byte {
	if len(assets.IconBytes) == 0 {
		return nil
	}
	return assets.IconBytes
}
