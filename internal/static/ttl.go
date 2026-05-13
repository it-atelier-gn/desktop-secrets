package static

type TTLOption struct {
	Label     string
	Minutes   int
	IsDefault bool
}

const DefaultTTL = 15

const DefaultRetrievalApproval = true

// ApprovalFactor* values for the approval_factor_required setting.
// `click` keeps the current behaviour: a click on the in-process Allow
// button is sufficient. `os_local` requires an additional OS-rendered
// authentication prompt (Windows Hello on Windows). Default is
// `click` until the OS factor has been validated in the field.
const (
	ApprovalFactorClick   = "click"
	ApprovalFactorOSLocal = "os_local"
)

const DefaultApprovalFactor = ApprovalFactorClick

// ApprovalFactorOption pairs the stored value with a tray-menu label.
// Only factors that have an implementation should appear here; new
// factors get added as the OS-prompt code lands per platform.
type ApprovalFactorOption struct {
	Label string
	Value string
}

var ApprovalFactorOptions = []ApprovalFactorOption{
	{Label: "Click only (default)", Value: ApprovalFactorClick},
	{Label: "OS authentication (Windows Hello)", Value: ApprovalFactorOSLocal},
}

// DefaultAutoApproveOnUnlock controls the "skip the approval dialog
// when an unlock prompt is going to be shown anyway" flow. Off by
// default: requiring two consent steps the first time a process asks
// for a secret is the safer posture, even if it's an extra click.
const DefaultAutoApproveOnUnlock = false

// ApprovalDurationUntilRestart is the sentinel for grants that last
// for the entire daemon lifetime. Stored as the Minutes value of the
// "Until daemon restart" option.
const ApprovalDurationUntilRestart = -1

var TTLOptions = []TTLOption{
	{Label: "5 minutes", Minutes: 5, IsDefault: false},
	{Label: "15 minutes (default)", Minutes: 15, IsDefault: true},
	{Label: "1 hour", Minutes: 60, IsDefault: false},
	{Label: "2 hours", Minutes: 120, IsDefault: false},
	{Label: "4 hours", Minutes: 240, IsDefault: false},
}

// ApprovalDurations are the choices on the retrieval-approval dialog.
// Mirrors TTLOptions plus an "until daemon restart" sentinel which is
// the default selection.
var ApprovalDurations = []TTLOption{
	{Label: "5 minutes", Minutes: 5, IsDefault: false},
	{Label: "15 minutes", Minutes: 15, IsDefault: false},
	{Label: "1 hour", Minutes: 60, IsDefault: false},
	{Label: "2 hours", Minutes: 120, IsDefault: false},
	{Label: "4 hours", Minutes: 240, IsDefault: false},
	{Label: "Until daemon restart", Minutes: ApprovalDurationUntilRestart, IsDefault: true},
}
