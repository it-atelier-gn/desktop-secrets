package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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

	out, err := client.RenderViaDaemon(cliCtx, st, []byte(b))
	if err != nil {
		log.Fatalf("render failed: %v", err)
	}

	fmt.Print(string(env.ExpandClientEnvBytes(out)))
}
