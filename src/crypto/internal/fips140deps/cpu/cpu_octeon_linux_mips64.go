// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package cpu

// Building with octeoncop2 asserts that the deployment has verified user-mode
// AES and GFM on its target. Linux MIPS HWCAP does not report these features.
const OcteonCOP2 = true
