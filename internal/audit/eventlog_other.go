//go:build !windows

package audit

func reportEvent(event, string) {}

func RegisterEventSource() error { return nil }
