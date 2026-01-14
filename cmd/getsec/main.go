package main

import (
	"context"
	"desktopsecrets/internal/client"
	"desktopsecrets/internal/server"
	"desktopsecrets/internal/version"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"
)

func main() {
	var versionFlag, daemonFlag bool
	flag.BoolVar(&versionFlag, "version", false, "print version")
	flag.BoolVar(&daemonFlag, "daemon", false, "run as daemon (tray + HTTP server)")
	flag.Parse()

	if versionFlag {
		version.PrintVersion()
		return
	}

	if daemonFlag {
		server.RunDaemon()
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

	fmt.Print(string(out))
}
