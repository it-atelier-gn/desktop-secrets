package static

type TTLOption struct {
	Label     string
	Minutes   int
	IsDefault bool
}

const DefaultTTL = 15

const DefaultRetrievalApproval = true

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
