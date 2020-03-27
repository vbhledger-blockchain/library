// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

package system

import "github.com/vbhledger-blockchain/library/gm/sm/x509"

func initSystemRoots() []*x509.Certificate {
	roots, _ := execSecurityRoots()
	return roots
}
