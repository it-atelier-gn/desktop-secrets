package desktopsecrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/client"
	"github.com/it-atelier-gn/desktop-secrets/internal/server"
)

var initialized bool

// Init checks if the process was launched as a daemon and runs it if so.
// Library users must call this at the top of main() and return if it returns true.
func Init() bool {
	initialized = true
	for _, arg := range os.Args[1:] {
		if arg == "--daemon" {
			server.RunDaemon()
			return true
		}
	}
	return false
}

func ResolveSecret(ref string) (string, error) {
	if !initialized {
		return "", fmt.Errorf("desktopsecrets.Init() must be called at the start of main()")
	}
	cliCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	st, err := client.EnsureDaemonRunning(cliCtx)
	if err != nil {
		return "", err
	}

	b := fmt.Sprintf("RESULT=%s", ref)

	out, warnings, err := client.RenderViaDaemon(cliCtx, st, []byte(b))
	if err != nil {
		return "", err
	}
	if warnings > 0 {
		return "", fmt.Errorf("desktopsecrets: failed to resolve %q (see daemon log / audit log)", ref)
	}

	result := strings.Split(string(out), "RESULT=")[1]

	return result, nil
}
