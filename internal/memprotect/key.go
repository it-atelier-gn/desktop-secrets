// Package memprotect provides in-memory protection for secrets cached during
// their TTL. Cached values are stored as AES-GCM ciphertext keyed by a
// process-local master key that is locked into RAM (VirtualLock on Windows,
// mlock on Unix) so it cannot be paged to disk.
//
// The protection target is offline disk artefacts (pagefile, hibernation file,
// crash dumps) and live memory forensic tools that scan process memory for
// high-entropy strings. It is not a defence against a debugger attached as
// the same user — that threat is handled separately by the IPC layer.
package memprotect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
)

var (
	initOnce  sync.Once
	initErr   error
	aead      cipher.AEAD
	masterKey []byte
)

func ensureInit() error {
	initOnce.Do(func() {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			initErr = fmt.Errorf("memprotect: generate master key: %w", err)
			return
		}
		_ = lockMemory(key)
		masterKey = key

		block, err := aes.NewCipher(masterKey)
		if err != nil {
			initErr = fmt.Errorf("memprotect: aes cipher: %w", err)
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			initErr = fmt.Errorf("memprotect: gcm: %w", err)
			return
		}
		aead = gcm
	})
	return initErr
}
