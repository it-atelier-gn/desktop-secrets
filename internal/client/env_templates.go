package client

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadAndCombineEnvTemplates reads all files matching `.env.tpl*` under the
// provided directory, sorts them by filename for deterministic ordering, and
// returns their concatenated contents separated by a single blank line.
func ReadAndCombineEnvTemplates(dir string) (string, error) {
	pattern := filepath.Join(dir, ".env.tpl*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}

	// If no files matched, return empty string and no error.
	if len(files) == 0 {
		return "", nil
	}

	sort.Strings(files)

	var parts []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		parts = append(parts, string(b))
	}

	// Join with one blank line between files to keep sections separated.
	combined := strings.Join(parts, "\n\n")
	return combined, nil
}
