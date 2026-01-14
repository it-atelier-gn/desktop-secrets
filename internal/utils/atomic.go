package utils

import (
	"sync/atomic"
	"time"
)

type AtomicBool struct{ v atomic.Bool }

func (a *AtomicBool) Load() bool   { return a.v.Load() }
func (a *AtomicBool) Store(b bool) { a.v.Store(b) }

type AtomicDuration struct{ v atomic.Int64 }

func (a *AtomicDuration) Load() time.Duration {
	return time.Duration(a.v.Load())
}
func (a *AtomicDuration) Store(d time.Duration) {
	a.v.Store(int64(d))
}
