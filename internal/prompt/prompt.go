package prompt

import (
	"desktopsecrets/assets"
	"desktopsecrets/internal/static"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

type Style int

const (
	StyleKeePass Style = iota
	StyleUser
)

type KeepassOptions struct {
	KeepassFile string
	UseKeyfile  bool
	Keyfile     string
	CurrentTTL  int
	Check       func(useKeyfile bool, keyfile string, password string, ttl int) error
}

type UserOptions struct {
	Prompt     string
	CurrentTTL int
}

type PromptResult struct {
	TTLMinutes int
	Keyfile    string
	UseKeyfile bool
	Password   string
}

func PromptForPassword(title string, style Style, keepOpts *KeepassOptions, userOpts *UserOptions) (*PromptResult, error) {
	resultCh := make(chan any, 1)
	a := fyne.CurrentApp()

	fyne.Do(func() {
		w := newWindow(a, title, resultCh)

		switch style {
		case StyleUser:
			if userOpts == nil {
				resultCh <- fmt.Errorf("userOpts cannot be nil for StyleUser")
				return
			}
			buildUserUI(w, userOpts, resultCh)

		case StyleKeePass:
			if keepOpts == nil {
				resultCh <- fmt.Errorf("keepOpts cannot be nil for StyleKeePass")
				return
			}
			buildKeePassUI(a, w, keepOpts, resultCh)

		default:
			resultCh <- fmt.Errorf("unknown style")
		}
	})

	res := <-resultCh
	if err, ok := res.(error); ok {
		return nil, err
	}
	if result, ok := res.(PromptResult); ok {
		return &result, nil
	}
	return nil, fmt.Errorf("unexpected result type")
}

func newWindow(a fyne.App, title string, resultCh chan any) fyne.Window {
	w := a.NewWindow(fmt.Sprintf("DesktopSecrets - %s", title))
	w.SetIcon(fyne.NewStaticResource("icon.ico", assets.IconBytes))
	w.Resize(fyne.NewSize(400, 170))
	w.CenterOnScreen()

	w.SetCloseIntercept(func() {
		resultCh <- fmt.Errorf("user cancelled")
		w.Close()
	})

	return w
}

func buildUserUI(w fyne.Window, opts *UserOptions, resultCh chan any) {
	cancel := func() {
		resultCh <- fmt.Errorf("user cancelled")
		w.Close()
	}

	ttlSelect, ttlMap := buildTTLSelect(opts.CurrentTTL)
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Enter Password")

	submit := func() {
		resultCh <- PromptResult{
			Password:   passwordEntry.Text,
			TTLMinutes: ttlMap[ttlSelect.Selected],
		}
		w.Close()
	}

	passwordEntry.OnSubmitted = func(_ string) { submit() }

	center := container.NewVBox(
		boldCentered(opts.Prompt),
		widget.NewLabel("Password:"),
		passwordEntry,
	)

	bottom := container.NewVBox(
		layout.NewSpacer(),
		container.NewHBox(
			widget.NewLabel("Remember for:"),
			ttlSelect,
			layout.NewSpacer(),
			widget.NewButton("OK", submit),
			widget.NewButton("Cancel", cancel),
		),
	)

	w.SetContent(container.NewBorder(nil, bottom, nil, nil, center))
	w.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
		if k.Name == fyne.KeyEscape {
			cancel()
		}
	})
	w.Show()
	w.Canvas().Focus(passwordEntry)
}

func buildKeePassUI(a fyne.App, w fyne.Window, opts *KeepassOptions, resultCh chan any) {
	cancel := func() {
		resultCh <- fmt.Errorf("user cancelled")
		w.Close()
	}

	useKeyfile := widget.NewCheck("Use keyfile", nil)
	useKeyfile.SetChecked(opts.UseKeyfile)

	keyfile := opts.Keyfile
	keyfileLabel := widget.NewLabel(keyfile)

	selectButton := widget.NewButton("Select", func() {
		temp := a.NewWindow("Select Keyfile")
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

	keyfileBox := container.NewHBox(widget.NewLabel("Keyfile:"), keyfileLabel, selectButton)
	useKeyfile.OnChanged = func(b bool) {
		if b {
			keyfileBox.Show()
		} else {
			keyfileBox.Hide()
		}
	}
	if !opts.UseKeyfile {
		keyfileBox.Hide()
	}

	ttlSelect, ttlMap := buildTTLSelect(opts.CurrentTTL)

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Enter Master Password")

	submit := func() {
		ttl := ttlMap[ttlSelect.Selected]
		useKF := useKeyfile.Checked

		if err := opts.Check(useKF, keyfile, passwordEntry.Text, ttl); err != nil {
			dialog.ShowError(err, w)
			return
		}

		resultCh <- PromptResult{
			Keyfile:    keyfile,
			UseKeyfile: useKF,
			Password:   passwordEntry.Text,
			TTLMinutes: ttl,
		}
		w.Close()
	}

	passwordEntry.OnSubmitted = func(_ string) { submit() }

	center := container.NewVBox(
		boldCentered(opts.KeepassFile),
		useKeyfile,
		keyfileBox,
		widget.NewLabel("Master Password:"),
		passwordEntry,
	)

	bottom := container.NewVBox(
		layout.NewSpacer(),
		container.NewHBox(
			widget.NewLabel("Remember for:"),
			ttlSelect,
			layout.NewSpacer(),
			widget.NewButton("OK", submit),
			widget.NewButton("Cancel", cancel),
		),
	)

	w.Resize(fyne.NewSize(400, 200))
	w.SetContent(container.NewBorder(nil, bottom, nil, nil, center))
	w.Canvas().SetOnTypedKey(func(k *fyne.KeyEvent) {
		if k.Name == fyne.KeyEscape {
			cancel()
		}
	})
	w.Show()

	if useKeyfile.Checked {
		w.Canvas().Focus(selectButton)
	} else {
		w.Canvas().Focus(passwordEntry)
	}
}

func buildTTLSelect(current int) (*widget.Select, map[string]int) {
	ttlSelect := widget.NewSelect(nil, nil)
	ttlMap := make(map[string]int)
	var labels []string

	for _, opt := range static.TTLOptions {
		labels = append(labels, opt.Label)
		ttlMap[opt.Label] = opt.Minutes
		if opt.IsDefault {
			ttlSelect.SetSelected(opt.Label)
		}
	}

	ttlSelect.Options = labels

	for label, mins := range ttlMap {
		if mins == current {
			ttlSelect.SetSelected(label)
			break
		}
	}

	return ttlSelect, ttlMap
}

func boldCentered(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.TextStyle = fyne.TextStyle{Bold: true}
	l.Alignment = fyne.TextAlignCenter
	return l
}
