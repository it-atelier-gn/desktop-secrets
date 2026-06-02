package server

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/it-atelier-gn/desktop-secrets/internal/keepass"
)

func normalizeFilePath(p string) string {
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return p
}

func browseInto(w fyne.Window, entry *widget.Entry) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		path := r.URI().Path()
		_ = r.Close()
		entry.SetText(normalizeFilePath(path))
	}, w)
}

type aliasRow struct {
	name   *widget.Entry
	file   *widget.Entry
	master *widget.Entry
}

func showAliasesWindow(app *AppState) {
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("KeePass Aliases")
		w.SetIcon(fyne.NewStaticResource("icon.ico", assetsIconBytes()))
		w.Resize(fyne.NewSize(680, 520))

		intro := widget.NewLabel(
			"Aliases give a KeePass database a short name, referenced with &name. " +
				"Master is optional — a secret reference resolved to unlock the vault " +
				"non-interactively. Paths may contain environment variables (e.g. $HOME).",
		)
		intro.Wrapping = fyne.TextWrapWord

		var rows []*aliasRow
		list := container.NewVBox()

		var rebuild func()
		addRow := func(name, file, master string) {
			r := &aliasRow{
				name:   widget.NewEntry(),
				file:   widget.NewEntry(),
				master: widget.NewEntry(),
			}
			r.name.SetText(name)
			r.file.SetText(file)
			r.master.SetText(master)
			r.name.SetPlaceHolder("name")
			r.file.SetPlaceHolder("path to .kdbx")
			r.master.SetPlaceHolder("master (optional secret ref)")
			rows = append(rows, r)
			rebuild()
		}

		rebuild = func() {
			list.RemoveAll()
			for i, r := range rows {
				idx := i
				browse := widget.NewButton("Browse…", func() { browseInto(w, rows[idx].file) })
				remove := widget.NewButton("Remove", func() {
					rows = append(rows[:idx], rows[idx+1:]...)
					rebuild()
				})
				fileRow := container.NewBorder(nil, nil, nil, browse, r.file)
				grid := container.New(layout.NewFormLayout(),
					widget.NewLabel("Name"), r.name,
					widget.NewLabel("File"), fileRow,
					widget.NewLabel("Master"), r.master,
				)
				list.Add(container.NewBorder(nil, nil, nil, remove, grid))
				list.Add(widget.NewSeparator())
			}
			list.Refresh()
		}

		for _, ai := range app.KP.Aliases() {
			rows = append(rows, &aliasRow{
				name:   entryWith(ai.Name, "name"),
				file:   entryWith(ai.File, "path to .kdbx"),
				master: entryWith(ai.Master, "master (optional secret ref)"),
			})
		}
		rebuild()

		addBtn := widget.NewButton("Add alias", func() { addRow("", "", "") })
		saveBtn := widget.NewButton("Save", func() {
			out := make([]keepass.AliasInfo, 0, len(rows))
			for _, r := range rows {
				if strings.TrimSpace(r.name.Text) == "" && strings.TrimSpace(r.file.Text) == "" {
					continue
				}
				out = append(out, keepass.AliasInfo{
					Name:   r.name.Text,
					File:   r.file.Text,
					Master: r.master.Text,
				})
			}
			if err := app.KP.SetAliases(out); err != nil {
				dialog.ShowError(err, w)
				return
			}
			w.Close()
		})
		cancelBtn := widget.NewButton("Cancel", func() { w.Close() })

		top := container.NewVBox(intro, addBtn, widget.NewSeparator())
		bottom := container.NewHBox(saveBtn, cancelBtn)
		w.SetContent(container.NewBorder(top, bottom, nil, nil, container.NewVScroll(list)))
		w.Show()
	})
}

type keyfileRow struct {
	vault   *widget.Entry
	keyfile *widget.Entry
}

func showKeyfilesWindow(app *AppState) {
	fyne.Do(func() {
		w := fyne.CurrentApp().NewWindow("KeePass Keyfiles")
		w.SetIcon(fyne.NewStaticResource("icon.ico", assetsIconBytes()))
		w.Resize(fyne.NewSize(680, 520))

		intro := widget.NewLabel(
			"Associate a KeePass database with a keyfile used to unlock it. The vault " +
				"is matched by its full path. These are also remembered automatically " +
				"after you pick a keyfile on an unlock prompt.",
		)
		intro.Wrapping = fyne.TextWrapWord

		var rows []*keyfileRow
		list := container.NewVBox()

		var rebuild func()
		rebuild = func() {
			list.RemoveAll()
			for i, r := range rows {
				idx := i
				browseVault := widget.NewButton("Browse…", func() { browseInto(w, rows[idx].vault) })
				browseKey := widget.NewButton("Browse…", func() { browseInto(w, rows[idx].keyfile) })
				remove := widget.NewButton("Remove", func() {
					rows = append(rows[:idx], rows[idx+1:]...)
					rebuild()
				})
				vaultRow := container.NewBorder(nil, nil, nil, browseVault, r.vault)
				keyRow := container.NewBorder(nil, nil, nil, browseKey, r.keyfile)
				grid := container.New(layout.NewFormLayout(),
					widget.NewLabel("Vault"), vaultRow,
					widget.NewLabel("Keyfile"), keyRow,
				)
				list.Add(container.NewBorder(nil, nil, nil, remove, grid))
				list.Add(widget.NewSeparator())
			}
			list.Refresh()
		}

		for _, ki := range app.KP.Keyfiles() {
			rows = append(rows, &keyfileRow{
				vault:   entryWith(ki.Vault, "path to .kdbx"),
				keyfile: entryWith(ki.Keyfile, "path to keyfile"),
			})
		}
		rebuild()

		addBtn := widget.NewButton("Add keyfile", func() {
			rows = append(rows, &keyfileRow{
				vault:   entryWith("", "path to .kdbx"),
				keyfile: entryWith("", "path to keyfile"),
			})
			rebuild()
		})
		saveBtn := widget.NewButton("Save", func() {
			out := make([]keepass.KeyfileInfo, 0, len(rows))
			for _, r := range rows {
				if strings.TrimSpace(r.vault.Text) == "" && strings.TrimSpace(r.keyfile.Text) == "" {
					continue
				}
				out = append(out, keepass.KeyfileInfo{
					Vault:   r.vault.Text,
					Keyfile: r.keyfile.Text,
				})
			}
			if err := app.KP.SetKeyfiles(out); err != nil {
				dialog.ShowError(err, w)
				return
			}
			w.Close()
		})
		cancelBtn := widget.NewButton("Cancel", func() { w.Close() })

		top := container.NewVBox(intro, addBtn, widget.NewSeparator())
		bottom := container.NewHBox(saveBtn, cancelBtn)
		w.SetContent(container.NewBorder(top, bottom, nil, nil, container.NewVScroll(list)))
		w.Show()
	})
}

func entryWith(text, placeholder string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(text)
	e.SetPlaceHolder(placeholder)
	return e
}
