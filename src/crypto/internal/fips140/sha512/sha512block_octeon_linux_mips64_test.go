// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package sha512

import (
	"crypto/internal/fips140"
	"os"
	"syscall"
	"testing"
)

func TestOcteonCompression(t *testing.T) {
	if fips140.Enabled {
		t.Skip("COP2 is disabled in FIPS mode")
	}
	page := os.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, 6*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(mem)
	for _, guard := range [][]byte{mem[:page], mem[5*page:]} {
		if err := syscall.Mprotect(guard, syscall.PROT_NONE); err != nil {
			t.Fatal(err)
		}
	}
	data := mem[page : 5*page]
	for i := range data {
		data[i] = byte(i*37 ^ i>>8)
	}
	for _, size := range []int{size224, size256, size384, size512} {
		for _, n := range []int{0, 1, octeonSHA512Batch - 1, octeonSHA512Batch, octeonSHA512Batch + 1, 2*octeonSHA512Batch + 1} {
			length := n * blockSize
			for offset := range 8 {
				for _, start := range []int{offset, page - blockSize/2 + offset, len(data) - length - offset} {
					got := Digest{size: size}
					got.Reset()
					want := got
					p := data[start:][:length:length]
					block(&got, p)
					blockGeneric(&want, p)
					if got.h != want.h {
						t.Fatalf("size=%d start=%d blocks=%d: got %016x, want %016x", size, start, n, got.h, want.h)
					}
				}
			}
		}
	}
}
