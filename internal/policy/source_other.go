//go:build !windows

package policy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const FactorEnforced = false

var (
	Location             = "/etc/desktop-secrets/policy.yaml"
	ErrElevationCanceled = errors.New("the administrator prompt was canceled")
)

type fileFloor struct {
	RetrievalApproval bool   `yaml:"retrieval_approval"`
	MinApprovalFactor string `yaml:"min_approval_factor"`
	MaxUnlockTTL      int    `yaml:"max_unlock_ttl"`
}

func Load() (Floor, error) {
	b, err := os.ReadFile(Location)
	if errors.Is(err, os.ErrNotExist) {
		return Floor{}, nil
	}
	if err != nil {
		return Floor{}, err
	}
	var ff fileFloor
	if err := yaml.Unmarshal(b, &ff); err != nil {
		return Floor{}, fmt.Errorf("%s: %w", Location, err)
	}
	return Floor{
		RetrievalApproval: ff.RetrievalApproval,
		MinApprovalFactor: normalizeFactor(ff.MinApprovalFactor),
		MaxUnlockTTL:      ff.MaxUnlockTTL,
	}, nil
}

func Save(f Floor) error {
	b, err := yaml.Marshal(fileFloor{
		RetrievalApproval: f.RetrievalApproval,
		MinApprovalFactor: normalizeFactor(f.MinApprovalFactor),
		MaxUnlockTTL:      f.MaxUnlockTTL,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(Location), 0o755); err != nil {
		return err
	}
	tmp := Location + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, Location)
}

func SaveElevated(f Floor) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.Command("pkexec", append([]string{exe, SetFlag}, f.Args()...)...).CombinedOutput()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && (exitErr.ExitCode() == 126 || exitErr.ExitCode() == 127) {
		return ErrElevationCanceled
	}
	if err != nil {
		return fmt.Errorf("writing %s failed: %v: %s", Location, err, out)
	}
	return nil
}
