package server

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
)

const daemonLogName = "daemon.log"
const daemonLogMaxSize = 1 << 20

func openDaemonLog(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, daemonLogName)
	if info, err := os.Stat(path); err == nil && info.Size() > daemonLogMaxSize {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

func setupDaemonLog(dir string) *os.File {
	f, err := openDaemonLog(dir)
	if err != nil {
		log.Printf("daemon log unavailable: %v", err)
		return nil
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		log.Printf("crash output unavailable: %v", err)
	}
	return f
}
