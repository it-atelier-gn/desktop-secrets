package desktopsecrets

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/buildmode"
	"github.com/it-atelier-gn/desktop-secrets/internal/client"
	"github.com/it-atelier-gn/desktop-secrets/internal/policy"
	"github.com/it-atelier-gn/desktop-secrets/internal/server"
)

var initialized bool

func Init() bool {
	initialized = true
	for _, arg := range os.Args[1:] {
		if arg == "--daemon" {
			server.RunDaemon()
			return true
		}
		if arg == "--allow-downgrade" {
			runAllowDowngrade()
			return true
		}
	}
	return false
}

func runAllowDowngrade() {
	if buildmode.Hardened {
		fmt.Fprintln(os.Stderr, "--allow-downgrade is not supported on the hardened build.")
		os.Exit(1)
	}
	exists, err := policy.MarkerExists()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not inspect hardened marker: %v\n", err)
		os.Exit(1)
	}
	if !exists {
		fmt.Println("No hardened marker present. Nothing to do.")
		return
	}
	fmt.Println("WARNING: this machine previously ran the hardened build, which requires")
	fmt.Println("Windows Hello / hardware-key approval for every retrieval.")
	fmt.Println()
	fmt.Println("Continuing will delete the hardened marker and let the lite build run")
	fmt.Println("with the weaker approval modes. Type 'yes' to continue, anything else to abort.")
	fmt.Print("> ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		fmt.Println("Aborted. Marker left in place.")
		os.Exit(1)
	}
	if err := policy.DeleteMarker(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to delete marker: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Hardened marker removed. You can now run the lite build.")
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
