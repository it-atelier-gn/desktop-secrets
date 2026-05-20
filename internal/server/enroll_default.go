//go:build !hardened

package server

func ensureHardenedEnrollment() error { return nil }
