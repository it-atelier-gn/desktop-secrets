//go:build hardened

package static

const (
	DefaultRetrievalApproval = true
	DefaultApprovalFactor    = ApprovalFactorOSLocal
)

var ApprovalModeOptions = []ApprovalModeOption{
	{
		Mode:  ApprovalModeAdvanced,
		Label: "Protected (Windows Hello / hardware key)",
		Description: "Every retrieval requires an OS-rendered authentication gesture " +
			"(Windows Hello or a hardware security key). User-space code cannot " +
			"replay the gesture, so a script or agent running as you cannot grant " +
			"itself access. This is the only mode the hardened build supports.",
	},
}
