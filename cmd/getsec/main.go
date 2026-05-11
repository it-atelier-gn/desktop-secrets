package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	desktopsecrets "github.com/it-atelier-gn/desktop-secrets"
	"github.com/it-atelier-gn/desktop-secrets/internal/client"
	"github.com/it-atelier-gn/desktop-secrets/internal/env"
	"github.com/it-atelier-gn/desktop-secrets/internal/version"
)

func main() {
	if desktopsecrets.Init() {
		return
	}

	var versionFlag bool
	flag.BoolVar(&versionFlag, "version", false, "print version")
	flag.Parse()

	if versionFlag {
		version.PrintVersion()
		return
	}

	args := flag.Args()

	cliCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	st, err := client.EnsureDaemonRunning(cliCtx)
	if err != nil {
		log.Fatalf("cannot start or reach daemon: %v", err)
	}

	b := strings.Join(args, "\n")

	out, warnings, err := client.RenderViaDaemon(cliCtx, st, []byte(b))
	if err != nil {
		log.Fatalf("render failed: %v", err)
	}

	fmt.Print(string(env.ExpandClientEnvBytes(out)))

	// One or more provider lookups failed (user cancelled, denied,
	// timed out, etc.). The body already carries diagnostic comments
	// for each unresolved line — exit non-zero so shell pipelines that
	// expect every requested secret notice the failure.
	if warnings > 0 {
		fmt.Fprintf(os.Stderr, "getsec: %d secret(s) failed to resolve (see comments above)\n", warnings)
		os.Exit(2)
	}
}
