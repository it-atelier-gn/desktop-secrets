package static

type TTLOption struct {
	Label     string
	Minutes   int
	IsDefault bool
}

const DefaultTTL = 15

const (
	ApprovalFactorClick   = "click"
	ApprovalFactorOSLocal = "os_local"
)

type ApprovalFactorOption struct {
	Label string
	Value string
}

var ApprovalFactorOptions = []ApprovalFactorOption{
	{Label: "Click only (default)", Value: ApprovalFactorClick},
	{Label: "OS authentication (Windows Hello)", Value: ApprovalFactorOSLocal},
}

type ApprovalMode string

const (
	ApprovalModeOff      ApprovalMode = "off"
	ApprovalModeStandard ApprovalMode = "standard"
	ApprovalModeAdvanced ApprovalMode = "advanced"
)

type ApprovalModeOption struct {
	Mode        ApprovalMode
	Label       string
	Description string
}

func DeriveApprovalMode(retrievalApproval bool, factor string) ApprovalMode {
	if !retrievalApproval {
		return ApprovalModeOff
	}
	if factor == ApprovalFactorOSLocal {
		return ApprovalModeAdvanced
	}
	return ApprovalModeStandard
}

func ApplyApprovalMode(m ApprovalMode) (retrievalApproval bool, factor string) {
	switch m {
	case ApprovalModeOff:
		return false, ApprovalFactorClick
	case ApprovalModeAdvanced:
		return true, ApprovalFactorOSLocal
	default:
		return true, ApprovalFactorClick
	}
}

const DefaultAutoApproveOnUnlock = false

const ApprovalDurationUntilRestart = -1
const ApprovalDurationOnce = 0

var TTLOptions = []TTLOption{
	{Label: "5 minutes", Minutes: 5, IsDefault: false},
	{Label: "15 minutes (default)", Minutes: 15, IsDefault: true},
	{Label: "1 hour", Minutes: 60, IsDefault: false},
	{Label: "2 hours", Minutes: 120, IsDefault: false},
	{Label: "4 hours", Minutes: 240, IsDefault: false},
}

const DefaultApprovalGrantMinutes = 5

var ApprovalDurations = []TTLOption{
	{Label: "Only this time", Minutes: ApprovalDurationOnce, IsDefault: false},
	{Label: "5 minutes", Minutes: 5, IsDefault: true},
	{Label: "15 minutes", Minutes: 15, IsDefault: false},
	{Label: "1 hour", Minutes: 60, IsDefault: false},
	{Label: "2 hours", Minutes: 120, IsDefault: false},
	{Label: "4 hours", Minutes: 240, IsDefault: false},
	{Label: "Until daemon restart", Minutes: ApprovalDurationUntilRestart, IsDefault: false},
}
