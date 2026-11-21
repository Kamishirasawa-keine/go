// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package gcm

import (
	"bytes"
	"crypto/internal/fips140"
	"crypto/internal/fips140/aes"
	"crypto/internal/fips140deps/cpu"
	"encoding/hex"
	"fmt"
	"testing"
)

func newCOP2TestGCM(t testing.TB, key []byte, nonceSize, tagSize int) *GCM {
	t.Helper()
	b, err := aes.New(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(b, nonceSize, tagSize)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCOP2Fallback(t *testing.T) {
	for _, tc := range []struct{ key, nonce, tag int }{
		{16, 12, 16}, {32, 12, 16}, {24, 12, 16}, {16, 13, 16}, {16, 12, 13},
	} {
		g := newCOP2TestGCM(t, make([]byte, tc.key), tc.nonce, tc.tag)
		nonce := make([]byte, tc.nonce)
		var key [4]uint64
		_, got := cop2Key(g, nonce, &key)
		want := cpu.OcteonCOP2 && !fips140.Enabled && tc.key != 24 && tc.nonce == 12 && tc.tag == 16
		if got != want {
			t.Fatalf("key/nonce/tag %v: COP2 dispatch = %v, want %v", tc, got, want)
		}
	}
}

func requireCOP2(t testing.TB) {
	t.Helper()
	if !cpu.OcteonCOP2 || fips140.Enabled {
		t.Skip("requires GODEBUG=octeoncop2=er4,fips140=off on ER4")
	}
}

// Run this test alone in a new process on the target before enabling COP2
// in a service. Nonempty plaintext exercises both AES and GFM.
func TestCOP2KnownAnswer(t *testing.T) {
	requireCOP2(t)
	for _, tc := range []struct {
		size int
		hex  string
	}{
		{16, "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"},
		{32, "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"},
	} {
		g := newCOP2TestGCM(t, make([]byte, tc.size), 12, 16)
		nonce, plain := make([]byte, 12), make([]byte, 16)
		want, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatal(err)
		}
		if got := g.Seal(nil, nonce, plain, nil); !bytes.Equal(got, want) {
			t.Fatalf("AES-%d Seal = %x, want %x", tc.size*8, got, want)
		}
		if got, err := g.Open(nil, nonce, want, nil); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("AES-%d Open = %x, %v", tc.size*8, got, err)
		}
	}
}

func TestCOP2AgainstGeneric(t *testing.T) {
	requireCOP2(t)
	for worker := range 16 {
		t.Run(fmt.Sprint(worker), func(t *testing.T) {
			t.Parallel()
			key := make([]byte, 16+16*(worker%2))
			for i := range key {
				key[i] = byte(i*7 + worker)
			}
			g := newCOP2TestGCM(t, key, 12, 16)
			nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, byte(worker)}
			for _, n := range []int{0, 1, 15, 16, 17, 511, 512, 513, 1024, 16384} {
				for _, aadLen := range []int{0, 1, 16, 513} {
					storage := make([]byte, 1+n+16)
					buf := storage[1:]
					plain := buf[:n]
					for i := range plain {
						plain[i] = byte(i*13 + worker)
					}
					aad := bytes.Repeat([]byte{byte(worker + n)}, aadLen+1)[1:]
					original := bytes.Clone(plain)
					want := make([]byte, n+16)
					sealGeneric(want, g, nonce[:], plain, aad)
					got := g.Seal(buf[:0], nonce[:], plain, aad)
					if !bytes.Equal(got, want) {
						t.Fatalf("in-place Seal mismatch for n=%d aad=%d", n, aadLen)
					}
					if got, err := g.Open(buf[:0], nonce[:], got, aad); err != nil || !bytes.Equal(got, original) {
						t.Fatalf("in-place Open mismatch for n=%d aad=%d: %v", n, aadLen, err)
					}
					copy(buf, want)
					buf[n] ^= 1
					if got, err := g.Open(buf[:0], nonce[:], buf, aad); err != errOpen || got != nil {
						t.Fatalf("bad tag: Open returned %x, %v", got, err)
					}
					if !bytes.Equal(buf[:n], make([]byte, n)) {
						t.Fatal("bad tag: output not cleared")
					}
				}
			}
		})
	}
}

func BenchmarkCOP2GCM(b *testing.B) {
	for _, n := range []int{64, 1024, 16 * 1024} {
		g := newCOP2TestGCM(b, make([]byte, 16), 12, 16)
		nonce, aad, plain := make([]byte, 12), make([]byte, 13), make([]byte, n)
		ciphertext := g.Seal(nil, nonce, plain, aad)
		b.Run(fmt.Sprintf("Seal/%d", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			out := make([]byte, 0, n+16)
			for b.Loop() {
				g.Seal(out, nonce, plain, aad)
			}
		})
		b.Run(fmt.Sprintf("Open/%d", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			out := make([]byte, 0, n)
			for b.Loop() {
				if _, err := g.Open(out, nonce, ciphertext, aad); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
