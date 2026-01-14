package main

import (
	"context"
	"desktopsecrets/internal/client"
	"desktopsecrets/internal/server"
	"desktopsecrets/internal/version"
	"flag"
	"fmt"
	"log"
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

	cliCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	st, err := client.EnsureDaemonRunning(cliCtx)
	if err != nil {
		log.Fatalf("cannot start or reach daemon: %v", err)
	}

	b, err := client.ReadAndCombineEnvTemplates(".")
	if err != nil {
		log.Fatalf("cannot read files: %v", err)
	}

	out, err := client.RenderViaDaemon(cliCtx, st, []byte(b))
	if err != nil {
		log.Fatalf("render failed: %v", err)
	}

	fmt.Print(string(out))
}
