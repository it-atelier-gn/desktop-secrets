package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/it-atelier-gn/desktop-secrets/internal/clientinfo"
)

type Decision string

const (
	DecisionAllowed      Decision = "allowed"
	DecisionCached       Decision = "cached"
	DecisionDenied       Decision = "denied"
	DecisionForgotten    Decision = "forgotten"
	DecisionUnlockFailed Decision = "unlock_failed"
	DecisionOSAuthFailed Decision = "os_auth_failed"
)

type Record struct {
	Time        time.Time `json:"time"`
	Decision    Decision  `json:"decision"`
	Factor      string    `json:"factor,omitempty"`
	ProviderKey string    `json:"provider_key"`
	ProviderRef string    `json:"provider_ref"`
	PID         int       `json:"pid"`
	Name        string    `json:"name,omitempty"`
	ExePath     string    `json:"exe_path,omitempty"`
	Cmdline     string    `json:"cmdline,omitempty"`
	Username    string    `json:"username,omitempty"`
	ParentPID   int       `json:"parent_pid,omitempty"`
	ParentName  string    `json:"parent_name,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type Logger struct {
	mu   sync.Mutex
	path string
}

func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Logger{path: filepath.Join(dir, "audit.log")}, nil
}

func (l *Logger) Log(rec Record) {
	if l == nil {
		return
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	reportEvent(eventFor(rec.Decision), string(line))
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s\n", line)
}

func (l *Logger) LogDecision(info clientinfo.Info, decision Decision, providerKey, providerRef, errMsg string) {
	l.LogDecisionWithFactor(info, decision, "", providerKey, providerRef, errMsg)
}

func (l *Logger) LogDecisionWithFactor(info clientinfo.Info, decision Decision, factor, providerKey, providerRef, errMsg string) {
	l.Log(Record{
		Decision:    decision,
		Factor:      factor,
		ProviderKey: providerKey,
		ProviderRef: providerRef,
		PID:         info.PID,
		Name:        info.Name,
		ExePath:     info.ExePath,
		Cmdline:     info.Cmdline,
		Username:    info.Username,
		ParentPID:   info.ParentPID,
		ParentName:  info.ParentName,
		Error:       errMsg,
	})
}

type event struct {
	ID      uint32
	Warning bool
}

const EventPolicyChanged uint32 = 300

func eventFor(d Decision) event {
	switch d {
	case DecisionAllowed:
		return event{ID: 100}
	case DecisionCached:
		return event{ID: 101}
	case DecisionDenied:
		return event{ID: 200, Warning: true}
	case DecisionForgotten:
		return event{ID: 201, Warning: true}
	case DecisionUnlockFailed:
		return event{ID: 202, Warning: true}
	case DecisionOSAuthFailed:
		return event{ID: 203, Warning: true}
	default:
		return event{ID: 299, Warning: true}
	}
}

func LogPolicyChange(msg string) {
	reportEvent(event{ID: EventPolicyChanged}, msg)
}
