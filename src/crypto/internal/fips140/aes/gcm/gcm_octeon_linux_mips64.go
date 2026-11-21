// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

package gcm

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140/aes"
	"crypto/internal/fips140/subtle"
	"crypto/internal/fips140deps/byteorder"
	"crypto/internal/fips140deps/cpu"
)

func checkGenericIsExpected() {}

type gcmPlatformData struct{}

func initGCM(g *GCM) {}

// Batch blocks both to amortize setup and to bound the async-unsafe region.
// Use aligned scratch words rather than relying on callers' buffer alignment.
const cop2Batch = 32

type cop2Block [2]uint64

//go:noescape
func cop2AES(key *[4]uint64, keyLen uint64, blocks *cop2Block, n int)

//go:noescape
func cop2GHASH(h, state, blocks *cop2Block, n int)

func cop2Key(g *GCM, nonce []byte, key *[4]uint64) (uint64, bool) {
	if !cpu.OcteonCOP2 || fips140.Enabled || len(nonce) != gcmStandardNonceSize || g.tagSize != gcmTagSize {
		return 0, false
	}
	return aes.COP2Key(&g.cipher, key)
}

func seal(out []byte, g *GCM, nonce, plaintext, data []byte) {
	var key [4]uint64
	keyLen, ok := cop2Key(g, nonce, &key)
	if !ok {
		sealGeneric(out, g, nonce, plaintext, data)
		return
	}

	j0, h, tagMask := cop2Init(&key, keyLen, nonce)
	ciphertext := out[:len(plaintext)]
	cop2Crypt(&key, keyLen, j0, ciphertext, plaintext)
	tag := cop2Auth(&h, tagMask, ciphertext, data)
	copy(out[len(plaintext):], tag[:])
}

func open(out []byte, g *GCM, nonce, ciphertext, data []byte) error {
	var key [4]uint64
	keyLen, ok := cop2Key(g, nonce, &key)
	if !ok {
		return openGeneric(out, g, nonce, ciphertext, data)
	}

	j0, h, tagMask := cop2Init(&key, keyLen, nonce)
	n := len(ciphertext) - gcmTagSize
	tag := cop2Auth(&h, tagMask, ciphertext[:n], data)
	if subtle.ConstantTimeCompare(tag[:], ciphertext[n:]) != 1 {
		return errOpen
	}
	cop2Crypt(&key, keyLen, j0, out, ciphertext[:n])
	return nil
}

// The standard 96-bit nonce is followed by a 32-bit counter. J0 has counter
// value one; the first payload block uses counter value two.
func cop2Init(key *[4]uint64, keyLen uint64, nonce []byte) (j0, h, tagMask cop2Block) {
	j0 = cop2Block{byteorder.BEUint64(nonce), uint64(byteorder.BEUint32(nonce[8:]))<<32 | 1}
	blocks := [2]cop2Block{{}, j0}
	cop2AES(key, keyLen, &blocks[0], len(blocks))
	return j0, blocks[0], blocks[1]
}

func cop2Crypt(key *[4]uint64, keyLen uint64, j0 cop2Block, out, in []byte) {
	var blocks [cop2Batch]cop2Block
	prefix := j0[1] &^ 0xffffffff
	ctr := uint32(j0[1]) + 1
	for len(in) != 0 {
		batch := min(len(in), len(blocks)*gcmBlockSize)
		n := (batch + gcmBlockSize - 1) / gcmBlockSize
		for i := range n {
			blocks[i] = cop2Block{j0[0], prefix | uint64(ctr)}
			ctr++
		}
		cop2AES(key, keyLen, &blocks[0], n)
		for _, mask := range blocks[:n] {
			if len(in) < gcmBlockSize {
				var tail [gcmBlockSize]byte
				byteorder.BEPutUint64(tail[:8], mask[0])
				byteorder.BEPutUint64(tail[8:], mask[1])
				subtle.XORBytes(out, in, tail[:len(in)])
				return
			}
			x := byteorder.BEUint64(in[:8]) ^ mask[0]
			y := byteorder.BEUint64(in[8:16]) ^ mask[1]
			byteorder.BEPutUint64(out[:8], x)
			byteorder.BEPutUint64(out[8:16], y)
			in, out = in[16:], out[16:]
		}
	}
}

func cop2Auth(h *cop2Block, tagMask cop2Block, ciphertext, data []byte) (tag [gcmTagSize]byte) {
	var state cop2Block
	var blocks [cop2Batch]cop2Block
	for _, input := range [2][]byte{data, ciphertext} {
		// Each input is separately zero-padded to a block boundary.
		for len(input) != 0 {
			n := 0
			for n < len(blocks) && len(input) >= gcmBlockSize {
				blocks[n] = cop2Block{byteorder.BEUint64(input[:8]), byteorder.BEUint64(input[8:16])}
				input = input[16:]
				n++
			}
			if n < len(blocks) && len(input) != 0 {
				var tail [gcmBlockSize]byte
				copy(tail[:], input)
				blocks[n] = cop2Block{byteorder.BEUint64(tail[:8]), byteorder.BEUint64(tail[8:])}
				input = nil
				n++
			}
			cop2GHASH(h, &state, &blocks[0], n)
		}
	}
	lengths := cop2Block{uint64(len(data)) * 8, uint64(len(ciphertext)) * 8}
	cop2GHASH(h, &state, &lengths, 1)
	byteorder.BEPutUint64(tag[:8], state[0]^tagMask[0])
	byteorder.BEPutUint64(tag[8:], state[1]^tagMask[1])
	return tag
}
