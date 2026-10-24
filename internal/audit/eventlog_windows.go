//go:build windows

package audit

import (
	"errors"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

const EventSource = "desktop-secrets"

func reportEvent(e event, msg string) {
	l, err := eventlog.Open(EventSource)
	if err != nil {
		return
	}
	defer l.Close()
	if e.Warning {
		_ = l.Warning(e.ID, msg)
		return
	}
	_ = l.Info(e.ID, msg)
}

func RegisterEventSource() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\EventLog\Application\`+EventSource, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return nil
	}
	if !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return eventlog.InstallAsEventCreate(EventSource, eventlog.Info|eventlog.Warning)
}
