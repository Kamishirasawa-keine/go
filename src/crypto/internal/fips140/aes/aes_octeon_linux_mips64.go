// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package aes

// COP2Key returns the original key as big-endian 64-bit words and the COP2
// key length selector. It is an internal helper for GCM. The generic key
// expansion on MIPS keeps the original key in the first words of enc.
func COP2Key(b *Block, key *[4]uint64) (length uint64, ok bool) {
	var n int
	switch b.rounds {
	case aes128Rounds:
		n = 2
	case aes256Rounds:
		n = 4
	default:
		return 0, false
	}
	*key = [4]uint64{}
	for i := range n {
		key[i] = uint64(b.enc[2*i])<<32 | uint64(b.enc[2*i+1])
	}
	return uint64(n - 1), true
}
