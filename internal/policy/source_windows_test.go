//go:build windows

package policy

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestRegistrySourceReadable(t *testing.T) {
	f, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, RegistryPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		if f != (Floor{}) {
			t.Fatalf("missing key must mean no minimum, got %+v", f)
		}
		return
	}
	if err != nil {
		t.Fatalf("open %s: %v", Location, err)
	}
	k.Close()
}
