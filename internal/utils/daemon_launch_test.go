package utils

import (
	"os"
	"slices"
	"testing"
)

func TestSetenvArgsForwardsPrefixedVariables(t *testing.T) {
	t.Setenv("DESKTOP_SECRETS_RUNTIME_DIR", `C:\rt`)
	t.Setenv("UNRELATED_VAR", "x")

	args := SetenvArgs([]string{StartFailuresEnv + "=breakaway: denied"})

	if !slices.Contains(args, `--setenv=DESKTOP_SECRETS_RUNTIME_DIR=C:\rt`) {
		t.Fatalf("runtime dir not forwarded: %v", args)
	}
	if !slices.Contains(args, "--setenv="+StartFailuresEnv+"=breakaway: denied") {
		t.Fatalf("extra variable not forwarded: %v", args)
	}
	for _, a := range args {
		if a == "--setenv=UNRELATED_VAR=x" {
			t.Fatalf("unrelated variable forwarded: %v", args)
		}
	}
}

func TestSetenvArgsPrefersExtraOverEnvironment(t *testing.T) {
	t.Setenv(StartFailuresEnv, "stale")
	args := SetenvArgs([]string{StartFailuresEnv + "=fresh"})
	n := 0
	for _, a := range args {
		if a == "--setenv="+StartFailuresEnv+"=fresh" {
			n++
		}
		if a == "--setenv="+StartFailuresEnv+"=stale" {
			t.Fatalf("stale value forwarded: %v", args)
		}
	}
	if n != 1 {
		t.Fatalf("expected fresh value once: %v", args)
	}
}

func TestApplySetenvArgsRoundTrip(t *testing.T) {
	t.Setenv("DESKTOP_SECRETS_CONFIG_FILE", "")
	t.Setenv("PATH_INJECT_TEST", "")

	ApplySetenvArgs([]string{
		"--daemon",
		"--setenv=DESKTOP_SECRETS_CONFIG_FILE=C:\\cfg\\a=b.yaml",
		"--setenv=PATH_INJECT_TEST=evil",
	})

	if got := os.Getenv("DESKTOP_SECRETS_CONFIG_FILE"); got != `C:\cfg\a=b.yaml` {
		t.Fatalf("config file = %q", got)
	}
	if got := os.Getenv("PATH_INJECT_TEST"); got != "" {
		t.Fatalf("unprefixed variable applied: %q", got)
	}
}
