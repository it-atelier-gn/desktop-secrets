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

// Availability mirrors the Windows UserConsentVerifierAvailability
// enum. The values are stable; on non-Windows platforms only
// AvailabilityUnsupported is returned.
type Availability int

const (
	// AvailabilityAvailable: at least one Windows Hello credential
	// (PIN, fingerprint, or face) is enrolled and ready.
	AvailabilityAvailable Availability = 0
	// AvailabilityDeviceNotPresent: no Hello-capable device on the
	// machine (also returned when no PIN credential is enrolled).
	AvailabilityDeviceNotPresent Availability = 1
	// AvailabilityNotConfiguredForUser: the device supports Hello but
	// the current user has not enrolled any credential.
	AvailabilityNotConfiguredForUser Availability = 2
	// AvailabilityDisabledByPolicy: group policy or MDM has blocked
	// Hello on this device.
	AvailabilityDisabledByPolicy Availability = 3
	// AvailabilityDeviceBusy: another consumer is currently using the
	// biometric device.
	AvailabilityDeviceBusy Availability = 4
	// AvailabilityUnsupported: this platform has no OS factor wired
	// up. Returned by CheckAvailability on non-Windows builds.
	AvailabilityUnsupported Availability = -1
)

// Reason returns a short human-readable label describing why the
// factor is unavailable. Empty for AvailabilityAvailable.
func (a Availability) Reason() string {
	switch a {
	case AvailabilityAvailable:
		return ""
	case AvailabilityDeviceNotPresent:
		return "no Windows Hello credential is enrolled on this device"
	case AvailabilityNotConfiguredForUser:
		return "Windows Hello is not configured for this user account"
	case AvailabilityDisabledByPolicy:
		return "Windows Hello is disabled by group policy"
	case AvailabilityDeviceBusy:
		return "the Windows Hello device is currently busy"
	case AvailabilityUnsupported:
		return "no OS-level authentication factor is available on this platform"
	default:
		return "Windows Hello is not available"
	}
}
