package main

import (
	"context"
	"desktopsecrets/internal/client"
	"desktopsecrets/internal/env"
	"desktopsecrets/internal/run"
	"desktopsecrets/internal/server"
	"desktopsecrets/internal/utils"
	"desktopsecrets/internal/version"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	var versionFlag, daemonFlag bool
	var shellFlag string
	var formatFlag string
	var onlyFlag string
	var excludeFlag string
	var applyOneLiner bool

	flag.BoolVar(&versionFlag, "version", false, "print version")
	flag.BoolVar(&daemonFlag, "daemon", false, "run as daemon (tray + HTTP server)")
	flag.StringVar(&shellFlag, "shell", "auto", "shell to output env for: auto|sh|pwsh|cmd (auto-detect if auto)")
	flag.StringVar(&formatFlag, "format", "env", "output format: env|json|raw")
	flag.StringVar(&onlyFlag, "only", "", "comma-separated list of variables to include (optional)")
	flag.StringVar(&excludeFlag, "exclude", "", "comma-separated list of variables to exclude (optional)")
	flag.BoolVar(&applyOneLiner, "apply-one-liner", false, "print a shell-specific one-liner to apply the env in the current shell")
	flag.Parse()

	if versionFlag {
		version.PrintVersion()
		return
	}

	if daemonFlag {
		server.RunDaemon()
		return
	}

	var shellToUse string
	if shellFlag == "auto" {
		shellToUse = utils.DetectShell()
	} else {
		shellToUse = shellFlag
	}

	// If apply-one-liner requested, print the one-liner and exit
	if applyOneLiner {
		// Determine exe name from os.Args[0] (strip path)
		exeName := os.Args[0]
		if strings.Contains(exeName, string(os.PathSeparator)) {
			parts := strings.Split(exeName, string(os.PathSeparator))
			exeName = parts[len(parts)-1]
		}
		one := oneLinerForShell(shellToUse, exeName)
		fmt.Println(one)
		return
	}

	args := flag.Args()

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

	parsed := env.ParseEnvBytes(out)

	// Apply only/exclude filters
	var onlyList, excludeList []string
	if strings.TrimSpace(onlyFlag) != "" {
		onlyList = strings.Split(onlyFlag, ",")
	}
	if strings.TrimSpace(excludeFlag) != "" {
		excludeList = strings.Split(excludeFlag, ",")
	}
	parsed = filterEnv(parsed, onlyList, excludeList)

	// If user asked for run
	if len(args) > 0 && args[0] == "run" {
		if len(args) < 2 {
			log.Fatalf("run requires a command to execute")
		}
		cmdName := args[1]
		cmdArgs := args[2:]
		if err := run.RunCommandWithEnv(cmdName, cmdArgs, parsed); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(interface{ ExitStatus() int }); ok {
					os.Exit(status.ExitStatus())
				}
			}
			log.Fatalf("command failed: %v", err)
		}
		return
	}

	// Output format
	switch strings.ToLower(strings.TrimSpace(formatFlag)) {
	case "env":
		printEnvForShell(parsed, shellToUse)
	case "json":
		printJSON(parsed)
	case "raw":
		for k, v := range parsed {
			fmt.Printf("%s=%s\n", k, v)
		}
	default:
		log.Fatalf("invalid --format value: %s (allowed: env, json)", formatFlag)
	}
}
