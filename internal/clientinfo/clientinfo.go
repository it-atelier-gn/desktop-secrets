// Package clientinfo resolves a process identifier to a human-readable
// description suitable for the retrieval-approval dialog.
package clientinfo

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ctxKey struct{}

// WithInfo attaches the full client Info to ctx so downstream callers
// can render both a short label and a detailed tooltip without
// re-resolving the PID.
func WithInfo(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

// InfoFromContext returns the Info previously set with WithInfo, or a
// zero-value Info if absent.
func InfoFromContext(ctx context.Context) Info {
	v, _ := ctx.Value(ctxKey{}).(Info)
	return v
}

// Info describes a client process. StartTime is opaque and OS-specific
// (Windows FILETIME / Linux /proc stat starttime / 0 if unavailable);
// combined with PID by the approval store to detect PID reuse.
type Info struct {
	PID        int
	Name       string // basename / image name
	ExePath    string // full path; empty when unavailable
	Cwd        string // working directory; empty when unavailable
	Cmdline    string // full command line; empty when unavailable
	Username   string // OS account running the process; empty when unavailable
	ParentPID  int
	ParentName string
	StartTime  uint64
}

// Display returns a one-line label for the dialog.
func (i Info) Display() string {
	if i.ExePath != "" {
		return fmt.Sprintf("PID %d — %s", i.PID, i.ExePath)
	}
	if i.Name != "" {
		return fmt.Sprintf("PID %d — %s", i.PID, i.Name)
	}
	return fmt.Sprintf("PID %d — unknown process", i.PID)
}

// Short returns just the executable path (or basename when only the
// image name is known), suitable for use as a primary label that
// reveals fuller details on hover.
func (i Info) Short() string {
	if i.ExePath != "" {
		return i.ExePath
	}
	if i.Name != "" {
		return i.Name
	}
	return "unknown process"
}

// Tooltip returns multi-line process details (PID + name + start time)
// intended for a mouse-over tooltip companion to Short().
func (i Info) Tooltip() string {
	var lines []string
	lines = append(lines, fmt.Sprintf("PID: %d", i.PID))
	if i.Name != "" {
		lines = append(lines, "Name: "+i.Name)
	}
	if i.Username != "" {
		lines = append(lines, "User: "+i.Username)
	}
	if i.Cmdline != "" {
		lines = append(lines, "Cmdline: "+i.Cmdline)
	}
	if i.ParentPID != 0 {
		if i.ParentName != "" {
			lines = append(lines, fmt.Sprintf("Parent: %d (%s)", i.ParentPID, i.ParentName))
		} else {
			lines = append(lines, fmt.Sprintf("Parent: %d", i.ParentPID))
		}
	}
	if i.Cwd != "" {
		lines = append(lines, "Cwd: "+i.Cwd)
	}
	if i.StartTime != 0 {
		if t, ok := startTimeToWallClock(i.StartTime); ok {
			lines = append(lines, "Start time: "+t.Format(time.RFC1123))
		} else {
			lines = append(lines, fmt.Sprintf("Start time: %d", i.StartTime))
		}
	}
	return strings.Join(lines, "\n")
}
