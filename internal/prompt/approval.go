package prompt

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/it-atelier-gn/desktop-secrets/assets"
	"github.com/it-atelier-gn/desktop-secrets/internal/static"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// Display caps for fields rendered in the approval dialog. Both originate
// from the client, so unbounded content could spoof the dialog layout.
const (
	maxProviderRefDisplay = 256
	maxClientDisplayLen   = 256
)

// sanitizeTooltip preserves newlines (multi-line tooltip layout) but
// collapses other control characters and caps total length. Same goal
// as sanitizeForDisplay: a crafted ClientDetails string must not be
// able to inject arbitrary control sequences into our overlay.
func sanitizeTooltip(s string) string {
	const maxLen = 1024
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > maxLen {
		out = out[:maxLen] + "..."
	}
	return out
}

// sanitizeForDisplay collapses control characters to spaces and truncates.
// A crafted ProviderRef with newlines would otherwise inject paragraphs in
// the same visual region as our own labels.
func sanitizeForDisplay(s string, maxLen int) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if maxLen > 0 && len(out) > maxLen {
		out = out[:maxLen] + "..."
	}
	return out
}

// ApprovalScope describes the breadth of an approval grant.
type ApprovalScope int

const (
	// ApprovalScopeProcess grants approval to the single calling PID.
	ApprovalScopeProcess ApprovalScope = iota
	// ApprovalScopeExecutable grants approval to any future process
	// running the same executable image.
	ApprovalScopeExecutable
)

// ApprovalRequest describes the secret retrieval that needs user
// consent. ProviderRef is shown verbatim in the dialog (e.g.
// "keepass(vault.kdbx | github/token)"). ClientDisplay is the
// formatted process info; ExePath is the executable path (if known).
// When ExePath is empty, the "Allow this executable" row is disabled.
type ApprovalRequest struct {
	ProviderRef      string
	ClientDisplay    string
	ExePath          string
	HasExistingGrant bool
}

// ApprovalDecision is the outcome of the approval dialog. When Allow
// is true, Scope and DurationMinutes carry the user's choice
// (DurationMinutes uses static.ApprovalDurationUntilRestart for
// "until daemon restart"). Forget signals revoke + evict; Allow and
// Forget are mutually exclusive.
type ApprovalDecision struct {
	Allow           bool
	Forget          bool
	Scope           ApprovalScope
	DurationMinutes int
}

// PromptApproval shows the standalone approval dialog (no unlock
// fields). Blocks the calling goroutine until the user chooses.
func PromptApproval(req ApprovalRequest) (ApprovalDecision, error) {
	resultCh := make(chan any, 1)
	a := fyne.CurrentApp()
	fyne.Do(func() {
		w := newApprovalWindow(a, "Allow secret access?", resultCh)
		buildApprovalUI(w, req, nil, resultCh)
	})
	res := <-resultCh
	if err, ok := res.(error); ok {
		return ApprovalDecision{}, err
	}
	if d, ok := res.(ApprovalDecision); ok {
		return d, nil
	}
	return ApprovalDecision{}, fmt.Errorf("unexpected approval result")
}

// PromptApprovalWithKeePass shows a single dialog combining approval
// header + KeePass unlock fields. The Check callback in opts is
// invoked when the user clicks an Allow button. On Check failure the
// dialog shows the error and stays open.
func PromptApprovalWithKeePass(req ApprovalRequest, opts *KeepassOptions) (ApprovalDecision, *PromptResult, error) {
	if opts == nil {
		return ApprovalDecision{}, nil, fmt.Errorf("KeepassOptions required")
	}
	resultCh := make(chan any, 1)
	a := fyne.CurrentApp()
	fyne.Do(func() {
		w := newApprovalWindow(a, "Allow secret access?", resultCh)
		buildApprovalUI(w, req, opts, resultCh)
	})
	res := <-resultCh
	if err, ok := res.(error); ok {
		return ApprovalDecision{}, nil, err
	}
	if combo, ok := res.(approvalUnlockResult); ok {
		return combo.Decision, combo.Unlock, nil
	}
	if d, ok := res.(ApprovalDecision); ok {
		return d, nil, nil
	}
	return ApprovalDecision{}, nil, fmt.Errorf("unexpected approval+unlock result")
}

type approvalUnlockResult struct {
	Decision ApprovalDecision
	Unlock   *PromptResult
}

func newApprovalWindow(a fyne.App, title string, resultCh chan any) fyne.Window {
	w := a.NewWindow(fmt.Sprintf("DesktopSecrets - %s", title))
	w.SetIcon(fyne.NewStaticResource("icon.ico", assets.IconBytes))
	w.Resize(fyne.NewSize(560, 280))
	w.CenterOnScreen()
	w.SetCloseIntercept(func() {
		resultCh <- ApprovalDecision{Allow: false}
		w.Close()
	})
	return w
}

func buildApprovalUI(w fyne.Window, req ApprovalRequest, kpOpts *KeepassOptions, resultCh chan any) {
	procDurationSelect, durationMap := buildApprovalDurationSelect()
	exeDurationSelect, _ := buildApprovalDurationSelect()

	processLbl := widget.NewLabel(sanitizeForDisplay(req.ClientDisplay, maxClientDisplayLen))
	processLbl.Wrapping = fyne.TextWrapWord
	refLbl := widget.NewLabel(sanitizeForDisplay(req.ProviderRef, maxProviderRefDisplay))
	refLbl.Wrapping = fyne.TextWrapWord
	refLbl.TextStyle = fyne.TextStyle{Monospace: true}

	header := container.NewVBox(
		widget.NewLabelWithStyle("Allow secret access?", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Process:"),
		processLbl,
		widget.NewLabel("Secret reference:"),
		refLbl,
	)

	// Optional KeePass unlock body.
	var keyfileBox *fyne.Container
	var passwordEntry *widget.Entry
	var useKeyfile *widget.Check
	keyfile := ""
	if kpOpts != nil {
		useKeyfile = widget.NewCheck("Use keyfile", nil)
		useKeyfile.SetChecked(kpOpts.UseKeyfile)
		keyfile = kpOpts.Keyfile
		keyfileLabel := widget.NewLabel(keyfile)

		selectButton := widget.NewButton("Select", func() {
			temp := fyne.CurrentApp().NewWindow("Select Keyfile")
			temp.SetIcon(fyne.NewStaticResource("icon.ico", assets.IconBytes))
			temp.Resize(fyne.NewSize(480, 370))
			temp.CenterOnScreen()
			dialog.ShowFileOpen(func(uri fyne.URIReadCloser, err error) {
				if err == nil && uri != nil {
					keyfile = uri.URI().Path()
					keyfileLabel.SetText(keyfile)
				}
				temp.Close()
			}, temp)
			temp.Show()
		})

		keyfileBox = container.NewHBox(widget.NewLabel("Keyfile:"), keyfileLabel, selectButton)
		useKeyfile.OnChanged = func(b bool) {
			if b {
				keyfileBox.Show()
			} else {
				keyfileBox.Hide()
			}
		}
		if !kpOpts.UseKeyfile {
			keyfileBox.Hide()
		}

		passwordEntry = widget.NewPasswordEntry()
		passwordEntry.SetPlaceHolder("Enter Master Password")
	}

	// Allow handler (shared by both rows). scope and durationSelect
	// determine what gets recorded.
	allowFn := func(scope ApprovalScope, durationSel *widget.Select) {
		ttl := durationMap[durationSel.Selected]
		decision := ApprovalDecision{Allow: true, Scope: scope, DurationMinutes: ttl}

		if kpOpts != nil {
			useKF := useKeyfile.Checked
			if err := kpOpts.Check(useKF, keyfile, passwordEntry.Text, ttlForUnlock(ttl, kpOpts.CurrentTTL)); err != nil {
				dialog.ShowError(err, w)
				return
			}
			resultCh <- approvalUnlockResult{
				Decision: decision,
				Unlock: &PromptResult{
					Keyfile:    keyfile,
					UseKeyfile: useKF,
					Password:   passwordEntry.Text,
					TTLMinutes: ttlForUnlock(ttl, kpOpts.CurrentTTL),
				},
			}
			w.Close()
			return
		}
		resultCh <- decision
		w.Close()
	}
	denyFn := func() {
		resultCh <- ApprovalDecision{Allow: false}
		w.Close()
	}
	forgetFn := func() {
		resultCh <- ApprovalDecision{Allow: false, Forget: true}
		w.Close()
	}

	allowProcessBtn := widget.NewButton("Allow this process", func() {
		allowFn(ApprovalScopeProcess, procDurationSelect)
	})
	allowProcessBtn.Importance = widget.HighImportance

	allowExeBtn := widget.NewButton("Allow this executable", func() {
		allowFn(ApprovalScopeExecutable, exeDurationSelect)
	})
	if req.ExePath == "" {
		allowExeBtn.Disable()
	}

	if passwordEntry != nil {
		passwordEntry.OnSubmitted = func(_ string) {
			allowFn(ApprovalScopeProcess, procDurationSelect)
		}
	}

	denyBtn := widget.NewButton("Deny", denyFn)
	forgetBtn := widget.NewButton("Forget", forgetFn)
	if !req.HasExistingGrant {
		forgetBtn.Disable()
	}

	processRow := container.NewHBox(
		allowProcessBtn,
		widget.NewLabel("for"),
		procDurationSelect,
	)
	exeRow := container.NewHBox(
		allowExeBtn,
		widget.NewLabel("for"),
		exeDurationSelect,
	)
	denyRow := container.NewHBox(
		layout.NewSpacer(),
		denyBtn,
		forgetBtn,
	)

	bottom := container.NewVBox(
		layout.NewSpacer(),
		processRow,
		exeRow,
		denyRow,
	)

	var center *fyne.Container
	if kpOpts != nil {
		center = container.NewVBox(
			header,
			widget.NewSeparator(),
			boldCentered(kpOpts.KeepassFile),
			useKeyfile,
			keyfileBox,
			widget.NewLabel("Master Password:"),
			passwordEntry,
		)
		w.Resize(fyne.NewSize(560, 440))
	} else {
		center = container.NewVBox(header)
	}

	w.SetContent(container.NewBorder(nil, bottom, nil, nil, center))
	w.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
		if k.Name == fyne.KeyEscape {
			denyFn()
		}
	})
	w.Show()
	if passwordEntry != nil {
		w.Canvas().Focus(passwordEntry)
	}
}

func buildApprovalDurationSelect() (*widget.Select, map[string]int) {
	sel := widget.NewSelect(nil, nil)
	m := make(map[string]int)
	var labels []string
	for _, opt := range static.ApprovalDurations {
		labels = append(labels, opt.Label)
		m[opt.Label] = opt.Minutes
		if opt.IsDefault {
			sel.SetSelected(opt.Label)
		}
	}
	sel.Options = labels
	return sel, m
}

// ttlForUnlock chooses how long to keep the unlocked vault. The user's
// approval-duration choice steers it: "until restart" (-1) maps to the
// daemon's current default unlock TTL since vaults must have a finite
// lifetime; numeric minutes map directly.
func ttlForUnlock(approvalMinutes, defaultUnlockMinutes int) int {
	if approvalMinutes <= 0 {
		return defaultUnlockMinutes
	}
	return approvalMinutes
}
