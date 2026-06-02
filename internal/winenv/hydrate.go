package winenv

type source struct {
	names  []string
	values map[string]string
}

func hydrate(
	sources []source,
	lookup func(string) (string, bool),
	expand func(string) string,
	set func(string, string),
) []string {
	var loaded []string
	for _, s := range sources {
		for _, name := range s.names {
			if name == "" {
				continue
			}
			if _, ok := lookup(name); ok {
				continue
			}
			raw, ok := s.values[name]
			if !ok {
				continue
			}
			set(name, expand(raw))
			loaded = append(loaded, name)
		}
	}
	return loaded
}
