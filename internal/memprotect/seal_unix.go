//go:build !windows

package memprotect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	initOnce sync.Once
	initErr  error
	lockErr  error
	aead     cipher.AEAD
	keyPage  []byte
)

func Init() error {
	if err := ensureInit(); err != nil {
		return err
	}
	return lockErr
}

func ensureInit() error {
	initOnce.Do(func() {
		page, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
		if err != nil {
			initErr = fmt.Errorf("memprotect: map key page: %w", err)
			return
		}
		if err := unix.Mlock(page); err != nil {
			lockErr = fmt.Errorf("memprotect: lock key page: %w", err)
		}
		excludeFromCoreDump(page)

		key := page[:32]
		if _, err := rand.Read(key); err != nil {
			initErr = fmt.Errorf("memprotect: generate master key: %w", err)
			return
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			initErr = fmt.Errorf("memprotect: aes cipher: %w", err)
			return
		}
		gcm, err := cipher.NewGCM(block)
		wipeObject(block)
		if err != nil {
			initErr = fmt.Errorf("memprotect: gcm: %w", err)
			return
		}
		if err := lockObject(gcm); err != nil && lockErr == nil {
			lockErr = fmt.Errorf("memprotect: lock cipher state: %w", err)
		}
		aead = gcm
		keyPage = page
	})
	return initErr
}

func objectBytes(v any) ([]byte, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil, errors.New("not a non-nil pointer")
	}
	size := rv.Elem().Type().Size()
	if size == 0 {
		return nil, errors.New("zero-sized object")
	}
	return unsafe.Slice((*byte)(rv.UnsafePointer()), size), nil
}

func lockObject(v any) error {
	b, err := objectBytes(v)
	if err != nil {
		return err
	}
	return unix.Mlock(b)
}

func wipeObject(v any) {
	if b, err := objectBytes(v); err == nil {
		Wipe(b)
	}
}

func seal(plaintext []byte) (*Sealed, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Sealed{nonce: nonce, ct: aead.Seal(nil, nonce, plaintext, nil), n: len(plaintext)}, nil
}

func open(s *Sealed) ([]byte, error) {
	if err := ensureInit(); err != nil {
		return nil, err
	}
	return aead.Open(nil, s.nonce, s.ct, nil)
}
