//go:build hardened && !windows

package server

import "errors"

func ensureHardenedEnrollment() error {
	return errors.New("hardened build is only supported on Windows")
}
