// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package cpu

import "crypto/internal/fips140deps/godebug"

func init() {
	// This setting asserts that the deployment has verified AES and GFM
	// support on this ER4. Do not issue trial COP2 instructions in-process.
	OcteonCOP2 = godebug.Value("#octeoncop2") == "er4"
}
