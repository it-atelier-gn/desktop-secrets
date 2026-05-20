//go:build !windows

package dpapi

import "errors"

var errUnsupported = errors.New("dpapi: only available on Windows")

func Protect(plain []byte) ([]byte, error)    { return nil, errUnsupported }
func Unprotect(cipher []byte) ([]byte, error) { return nil, errUnsupported }
