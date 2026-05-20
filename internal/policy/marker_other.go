//go:build !windows

package policy

func MarkerExists() (bool, error) { return false, nil }
func WriteMarker() error          { return nil }
func DeleteMarker() error         { return nil }
