package winenv

import (
	"slices"
	"strings"
	"testing"
)

func TestHydrateFillsMissingOnly(t *testing.T) {
	env := map[string]string{"USERPROFILE": "C:\\Users\\existing"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	set := func(k, v string) { env[k] = v }
	identity := func(v string) string { return v }

	sources := []source{
		{
			names:  []string{"USERPROFILE", "APPDATA"},
			values: map[string]string{"USERPROFILE": "C:\\Users\\reg", "APPDATA": "C:\\Users\\reg\\AppData\\Roaming"},
		},
	}

	loaded := hydrate(sources, lookup, identity, set)

	if env["USERPROFILE"] != "C:\\Users\\existing" {
		t.Errorf("existing var clobbered: %q", env["USERPROFILE"])
	}
	if env["APPDATA"] != "C:\\Users\\reg\\AppData\\Roaming" {
		t.Errorf("missing var not filled: %q", env["APPDATA"])
	}
	if !slices.Equal(loaded, []string{"APPDATA"}) {
		t.Errorf("loaded = %v, want [APPDATA]", loaded)
	}
}

func TestHydrateUserSourceWinsOverSystem(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	set := func(k, v string) { env[k] = v }
	identity := func(v string) string { return v }

	sources := []source{
		{names: []string{"FOO"}, values: map[string]string{"FOO": "user"}},
		{names: []string{"FOO"}, values: map[string]string{"FOO": "system"}},
	}

	hydrate(sources, lookup, identity, set)

	if env["FOO"] != "user" {
		t.Errorf("FOO = %q, want user (earlier source wins)", env["FOO"])
	}
}

func TestHydrateExpandsAgainstAlreadySetVars(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	set := func(k, v string) { env[k] = v }
	expand := func(v string) string {
		return strings.ReplaceAll(v, "%USERPROFILE%", env["USERPROFILE"])
	}

	sources := []source{
		{names: []string{"USERPROFILE"}, values: map[string]string{"USERPROFILE": "C:\\Users\\me"}},
		{names: []string{"TOOLS"}, values: map[string]string{"TOOLS": "%USERPROFILE%\\tools"}},
	}

	hydrate(sources, lookup, expand, set)

	if env["TOOLS"] != "C:\\Users\\me\\tools" {
		t.Errorf("TOOLS = %q, want expanded path", env["TOOLS"])
	}
}

func TestHydrateSkipsEmptyName(t *testing.T) {
	env := map[string]string{}
	set := func(k, v string) { env[k] = v }
	loaded := hydrate(
		[]source{{names: []string{""}, values: map[string]string{"": "x"}}},
		func(string) (string, bool) { return "", false },
		func(v string) string { return v },
		set,
	)
	if len(loaded) != 0 || len(env) != 0 {
		t.Errorf("empty name should be skipped: loaded=%v env=%v", loaded, env)
	}
}
