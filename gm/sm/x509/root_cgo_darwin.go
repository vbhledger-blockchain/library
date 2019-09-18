// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo,!arm,!arm64,!ios

package x509

import "C"
import (
	"errors"
	"unsafe"
)

func loadSystemRoots() (*CertPool, error) {
	roots := NewCertPool()

	var data C.CFDataRef = 0
	var untrustedData C.CFDataRef = 0
	err := C.FetchPEMRoots(&data, &untrustedData, C.bool(debugDarwinRoots))
	if err == -1 {
		return nil, errors.New("crypto/x509: failed to load darwin system roots with cgo")
	}

	defer C.CFRelease(C.CFTypeRef(data))
	buf := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data)))
	roots.AppendCertsFromPEM(buf)
	if untrustedData == 0 {
		return roots, nil
	}
	defer C.CFRelease(C.CFTypeRef(untrustedData))
	buf = C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(untrustedData)), C.int(C.CFDataGetLength(untrustedData)))
	untrustedRoots := NewCertPool()
	untrustedRoots.AppendCertsFromPEM(buf)

	trustedRoots := NewCertPool()
	for _, c := range roots.certs {
		if !untrustedRoots.contains(c) {
			trustedRoots.AddCert(c)
		}
	}
	return trustedRoots, nil
}
