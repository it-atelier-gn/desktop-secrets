// Package osauth gates a recorded approval behind an OS-rendered
// authentication prompt that user-space input cannot satisfy
// (Windows Hello, Touch ID, polkit). The approval dialog still shows
// process/scope/duration; this package runs *after* the user clicks
// Allow and only on success does the caller persist the grant.
//
// The goal is to defeat the "agent running as the user clicks Allow"
// threat by requiring a gesture that the agent cannot reproduce. The
// approval dialog itself stays — this is the second factor, not a
// replacement.
package osauth

import "errors"

// Factor identifies which authentication surface produced a grant.
// Recorded in the audit log so a reviewer can distinguish "user
// clicked" from "user passed Windows Hello".
type Factor string

const (
	// FactorClick: only the in-process approval dialog was used.
	// Vulnerable to user-space input injection — should be deprecated
	// once stronger factors are stable.
	FactorClick Factor = "click"
	// FactorOSLocal: an OS-rendered prompt (Windows Hello /
	// Touch ID / polkit) confirmed the grant.
	FactorOSLocal Factor = "os_local"
)

// ErrUnsupported is returned by Verify on platforms where no OS factor
// is wired up yet. Callers should treat it as "factor not available",
// not as an authentication failure.
var ErrUnsupported = errors.New("osauth: not implemented on this platform")

// ErrCanceled is returned when the OS prompt is dismissed without a
// successful verification (user cancel, timeout, retries exhausted).
var ErrCanceled = errors.New("osauth: user canceled or did not verify")
