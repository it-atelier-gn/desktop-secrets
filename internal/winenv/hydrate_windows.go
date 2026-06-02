//go:build windows

package winenv

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

func Hydrate() []string {
	srcs := readRegistrySources()
	expand := func(v string) string {
		if e, err := registry.ExpandString(v); err == nil {
			return e
		}
		return v
	}
	return hydrate(srcs, os.LookupEnv, expand, func(k, v string) { _ = os.Setenv(k, v) })
}

func readRegistrySources() []source {
	specs := []struct {
		root registry.Key
		path string
	}{
		{registry.CURRENT_USER, `Volatile Environment`},
		{registry.CURRENT_USER, `Environment`},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`},
	}

	var out []source
	for _, sp := range specs {
		k, err := registry.OpenKey(sp.root, sp.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(0)
		if err != nil {
			k.Close()
			continue
		}
		vals := make(map[string]string, len(names))
		for _, n := range names {
			v, _, err := k.GetStringValue(n)
			if err != nil {
				continue
			}
			vals[n] = v
		}
		k.Close()
		out = append(out, source{names: names, values: vals})
	}
	return out
}
