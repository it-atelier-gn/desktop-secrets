package desktopsecrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/client"
	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
	"github.com/it-atelier-gn/desktop-secrets/internal/server"
	"github.com/it-atelier-gn/desktop-secrets/internal/utils"
)

var initialized bool

func Init() bool {
	initialized = true
	for _, arg := range os.Args[1:] {
		if arg == "--daemon" {
			utils.ApplySetenvArgs(os.Args[1:])
			server.RunDaemon()
			return true
		}
	}
	if len(os.Args) > 1 && os.Args[1] == policy.SetFlag {
		runSetMachinePolicy(os.Args[2:])
		return true
	}
	return false
}

func runSetMachinePolicy(args []string) {
	f, err := policy.ParseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", policy.SetFlag, err)
		os.Exit(2)
	}
	if err := policy.Save(f); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write %s: %v\n", policy.Location, err)
		os.Exit(1)
	}
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
