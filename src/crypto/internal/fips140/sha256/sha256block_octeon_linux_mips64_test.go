// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package sha256

import (
	"crypto/internal/fips140"
	"testing"
)

func TestOcteonCompression(t *testing.T) {
	if fips140.Enabled {
		t.Skip("COP2 is disabled in FIPS mode")
	}
	var buf [(2*octeonSHA256Batch+1)*blockSize + 7]byte
	for i := range buf {
		buf[i] = byte(i*37 ^ i>>8)
	}
	for _, is224 := range []bool{false, true} {
		for offset := range 8 {
			for _, n := range []int{0, 1, 15, 16, 17, 32, 33} {
				p := buf[offset:][:n*blockSize]
				got := Digest{is224: is224}
				got.Reset()
				want := got
				block(&got, p)
				blockGeneric(&want, p)
				if got.h != want.h {
					t.Fatalf("is224=%v offset=%d blocks=%d: got %08x, want %08x", is224, offset, n, got.h, want.h)
				}
			}
		}
	}
}
