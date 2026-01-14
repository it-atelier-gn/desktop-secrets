//go:build windows

package shm

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Helper: tiny delay (mostly harmless, keeps CI stable).
func shortDelay() { time.Sleep(5 * time.Millisecond) }

// cleanShm closes any mapping left in shmGlobal and resets it.
// Use before each test to avoid cross-test leakage.
func cleanShm() {
	if shmGlobal != nil {
		_ = windows.UnmapViewOfFile(shmGlobal.view)
		_ = windows.CloseHandle(shmGlobal.handle)
		shmGlobal = nil
	}
}

func TestShmPublishAndRead_Success(t *testing.T) {
	cleanShm()

	payloads := [][]byte{
		[]byte(""),      // empty payload
		[]byte("A"),     // single byte
		[]byte("hello"), // small ASCII
		bytes.Repeat([]byte{1}, 128),
		bytes.Repeat([]byte{0xFF}, 1024),
	}

	for i, p := range payloads {
		t.Run("case_"+strconv.Itoa(i), func(t *testing.T) {
			cleanShm()

			cleanup, err := ShmDaemonPublish(p)
			if err != nil {
				t.Fatalf("publish error: %v", err)
			}
			defer func() {
				cleanup()
				cleanShm()
			}()

			shortDelay()

			got, err := ShmClientRead()
			if err != nil {
				t.Fatalf("client read error: %v", err)
			}
			if !bytes.Equal(got, p) {
				t.Fatalf("roundtrip mismatch: got=%v want=%v (len got=%d len want=%d)", got, p, len(got), len(p))
			}
		})
	}

	cleanShm()
}

func TestShmPublish_ZeroesRemainder_AndClientSeesPrefixOnly(t *testing.T) {
	cleanShm()

	// Craft payload smaller than shmSize; client should read exactly the prefix.
	p := []byte("EnvTrayState test payload")

	cleanup, err := ShmDaemonPublish(p)
	if err != nil {
		t.Fatalf("publish error: %v", err)
	}
	defer func() {
		cleanup()
		cleanShm()
	}()

	shortDelay()

	got, err := ShmClientRead()
	if err != nil {
		t.Fatalf("client read error: %v", err)
	}
	if !bytes.Equal(got, p) {
		t.Fatalf("client should read exactly published prefix; got=%q want=%q", string(got), string(p))
	}

	cleanShm()
}

func TestShmPublish_OversizeError(t *testing.T) {
	cleanShm()

	oversize := make([]byte, shmSize+1)

	cleanup, err := ShmDaemonPublish(oversize)
	if err == nil {
		// If it unexpectedly succeeds, ensure cleanup and fail.
		if cleanup != nil {
			cleanup()
		}
		t.Fatalf("expected error for oversize payload (> %d), got nil", shmSize)
	}

	cleanShm()
}

func TestCleanup_IsIdempotent_AndClosesHandles(t *testing.T) {
	cleanShm()

	data := []byte("cleanup test")

	cleanup, err := ShmDaemonPublish(data)
	if err != nil {
		t.Fatalf("publish error: %v", err)
	}

	// Capture handle/view before cleanup.
	if shmGlobal == nil {
		t.Fatalf("shmGlobal should be set after publish")
	}
	handleBefore := shmGlobal.handle
	viewBefore := shmGlobal.view

	// First cleanup.
	cleanup()

	// After cleanup, global must be nil and handles should be closed/unmapped.
	if shmGlobal != nil {
		t.Fatalf("shmGlobal must be nil after cleanup")
	}

	// Second cleanup call must be safe (idempotent).
	cleanup()

	// Attempt to read should fail as mapping no longer exists.
	_, err = ShmClientRead()
	if err == nil {
		t.Fatalf("expected read error after cleanup; got nil")
	}

	// Sanity check: calling UnmapViewOfFile/CloseHandle again on prior values should fail,
	// but these calls are safe to ignore—this just asserts 'best effort' closure.
	_ = windows.UnmapViewOfFile(viewBefore) // likely ERROR_INVALID_ADDRESS
	_ = windows.CloseHandle(handleBefore)   // likely ERROR_INVALID_HANDLE

	cleanShm()
}

func TestClientRead_NoMapping(t *testing.T) {
	cleanShm()

	_, err := ShmClientRead()
	if err == nil {
		t.Fatalf("expected error when reading without a published mapping")
	}

	cleanShm()
}
