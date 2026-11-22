// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package sha256

import "crypto/internal/fips140"

// Limit time spent in assembly without an asynchronous preemption point.
const octeonSHA256Batch = 64 // 4 KiB per assembly call.

//go:noescape
func blockOcteon(state *[8]uint32, input *byte, n int)

func block(dig *Digest, p []byte) {
	if fips140.Enabled {
		blockGeneric(dig, p)
		return
	}
	for len(p) >= blockSize {
		n := min(len(p)/blockSize, octeonSHA256Batch)
		blockOcteon(&dig.h, &p[0], n)
		p = p[n*blockSize:]
	}
}
