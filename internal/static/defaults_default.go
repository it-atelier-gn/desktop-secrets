//go:build !hardened

package static

const (
	DefaultRetrievalApproval = false
	DefaultApprovalFactor    = ApprovalFactorClick
)

var ApprovalModeOptions = []ApprovalModeOption{
	{
		Mode:  ApprovalModeOff,
		Label: "Off",
		Description: "No approval prompt. Any program running as you that can reach the " +
			"daemon receives secrets as soon as the source vault is unlocked. " +
			"Convenient, but not safe against background agents or a compromised " +
			"dependency in your toolchain.",
	},
	{
		Mode:  ApprovalModeStandard,
		Label: "Standard",
		Description: "An Allow / Deny dialog appears for every retrieval that isn't " +
			"already covered by a live grant. Blocks headless processes that have " +
			"no UI. A local agent able to click buttons in your session can still " +
			"satisfy it. For agent-safe handling, install the hardened build.",
	},
}
