//go:build !windows

package osauth

// Verify is a stub on non-Windows platforms. Callers should treat
// ErrUnsupported as "fall through to click-only" so other OSes keep
// building until their factor is implemented.
func Verify(reason string) (Factor, error) {
	return FactorClick, ErrUnsupported
}

// Available reports whether an OS factor is wired up on this build.
func Available() bool { return false }

// CheckAvailability always returns AvailabilityUnsupported on
// platforms without an OS factor implementation.
func CheckAvailability() Availability { return AvailabilityUnsupported }
