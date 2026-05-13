// Package audit records every retrieval-approval decision the daemon
// makes. One JSON Lines record per attempt, appended to a file in the
// user's settings directory. Used for after-the-fact incident review:
// "which process got which secret when, and was it via a fresh
// approval, a cached grant, or an auto-approve on unlock".
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

// Decision enumerates the outcomes worth distinguishing in the log.
type Decision string

const (
	DecisionAllowed       Decision = "allowed"        // user clicked Allow on the approval dialog
	DecisionAutoApproved  Decision = "auto_approved"  // approval skipped because the unlock prompt acted as consent
	DecisionCached        Decision = "cached"         // existing live grant matched, no prompt shown
	DecisionDenied        Decision = "denied"         // user clicked Deny / closed the approval dialog
	DecisionForgotten     Decision = "forgotten"      // user clicked Forget on the approval dialog
	DecisionUnlockFailed  Decision = "unlock_failed"  // password / master-password prompt errored out
	DecisionOSAuthFailed  Decision = "os_auth_failed" // user clicked Allow but the OS factor (Hello / etc.) did not verify
)

// Record is one audit-log entry, serialised as a single JSON line.
//
// Factor identifies which authentication surface produced the grant
// (`click`, `os_local`, ...). Set on allowed / auto_approved /
// cached records so a reviewer can distinguish "user clicked Allow"
// from "user passed Windows Hello". Empty on denial records.
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

// Logger appends Records to a JSON Lines file. Safe for concurrent use.
// A nil *Logger is valid and silently drops events, so callers can
// avoid sprinkling nil checks at call sites.
type Logger struct {
	mu   sync.Mutex
	path string
}

// New returns a Logger that appends to filepath.Join(dir, "audit.log").
// The directory is created if it does not exist. Errors from directory
// creation are returned; per-write errors are swallowed (the daemon
// must not fail a secret retrieval because the audit log is unwritable
// — operators can detect this via the absence of expected records).
func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Logger{path: filepath.Join(dir, "audit.log")}, nil
}

// Log appends rec to the audit log. Best-effort: errors are silently
// swallowed for the reason described on New. Records lacking a time
// are stamped with the current time.
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
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s\n", line)
}

// LogDecision is a convenience wrapper that populates the process
// fields from an InfoFromContext-style clientinfo.Info and writes the
// record.
func (l *Logger) LogDecision(info clientinfo.Info, decision Decision, providerKey, providerRef, errMsg string) {
	l.LogDecisionWithFactor(info, decision, "", providerKey, providerRef, errMsg)
}

// LogDecisionWithFactor writes a decision and records which
// authentication factor produced the grant. Use for allowed /
// auto_approved / cached records; for denials pass factor="".
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
