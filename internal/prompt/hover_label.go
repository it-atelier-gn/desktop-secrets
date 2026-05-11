package prompt

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// hoverLabel is a text label that pops up a tooltip overlay when the
// pointer hovers over it. Fyne v2 has no built-in tooltip widget, so
// we wire desktop.Hoverable to a PopUp manually.
type hoverLabel struct {
	widget.BaseWidget

	text    string
	tooltip string
	win     fyne.Window
	popup   *widget.PopUp
}

func newHoverLabel(text, tooltip string, win fyne.Window) *hoverLabel {
	h := &hoverLabel{text: text, tooltip: tooltip, win: win}
	h.ExtendBaseWidget(h)
	return h
}

func (h *hoverLabel) CreateRenderer() fyne.WidgetRenderer {
	lbl := widget.NewLabel(h.text)
	lbl.Truncation = fyne.TextTruncateEllipsis
	return widget.NewSimpleRenderer(lbl)
}

// desktop.Hoverable

func (h *hoverLabel) MouseIn(ev *desktop.MouseEvent) {
	if h.tooltip == "" || h.win == nil {
		return
	}
	if h.popup != nil {
		h.popup.Hide()
	}

	bg := canvas.NewRectangle(theme.Color(theme.ColorNameOverlayBackground))
	bg.StrokeColor = theme.Color(theme.ColorNameInputBorder)
	bg.StrokeWidth = 1
	bg.CornerRadius = 4

	// TextWrapOff lets the label size itself to its widest line; without
	// this, the PopUp gives the label a zero width and word-wrap breaks
	// every character onto its own line.
	txt := widget.NewLabel(h.tooltip)
	txt.Wrapping = fyne.TextWrapOff

	content := container.NewStack(bg, container.NewPadded(txt))

	h.popup = widget.NewPopUp(content, h.win.Canvas())
	h.popup.Resize(content.MinSize())
	h.popup.ShowAtPosition(ev.AbsolutePosition.AddXY(12, 12))
}

func (h *hoverLabel) MouseMoved(ev *desktop.MouseEvent) {
	if h.popup != nil {
		h.popup.Move(ev.AbsolutePosition.AddXY(12, 12))
	}
}

func (h *hoverLabel) MouseOut() {
	if h.popup != nil {
		h.popup.Hide()
		h.popup = nil
	}
}
