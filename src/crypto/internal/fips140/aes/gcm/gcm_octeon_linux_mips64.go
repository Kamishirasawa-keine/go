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
func cop2GHASH(h, state *cop2Block, blocks *byte, n int)

//go:noescape
func cop2CTR(key *[4]uint64, keyLen uint64, dst, src *byte, n int, hi, prefix, ctr uint64)

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
	prefix := j0[1] &^ 0xffffffff
	ctr := uint32(j0[1]) + 1
	for len(in) >= gcmBlockSize {
		n := min(cop2Batch, len(in)/gcmBlockSize)
		cop2CTR(key, keyLen, &out[0], &in[0], n, j0[0], prefix, uint64(ctr))
		ctr += uint32(n)
		in, out = in[n*gcmBlockSize:], out[n*gcmBlockSize:]
	}
	if len(in) != 0 {
		mask := cop2Block{j0[0], prefix | uint64(ctr)}
		cop2AES(key, keyLen, &mask, 1)
		var tail [gcmBlockSize]byte
		byteorder.BEPutUint64(tail[:8], mask[0])
		byteorder.BEPutUint64(tail[8:], mask[1])
		subtle.XORBytes(out, in, tail[:len(in)])
	}
}

func cop2Auth(h *cop2Block, tagMask cop2Block, ciphertext, data []byte) (tag [gcmTagSize]byte) {
	var state cop2Block
	for _, input := range [2][]byte{data, ciphertext} {
		for len(input) >= gcmBlockSize {
			n := min(cop2Batch, len(input)/gcmBlockSize)
			cop2GHASH(h, &state, &input[0], n)
			input = input[n*gcmBlockSize:]
		}
		// Each input is separately zero-padded to a block boundary.
		if len(input) != 0 {
			var tail [gcmBlockSize]byte
			copy(tail[:], input)
			cop2GHASH(h, &state, &tail[0], 1)
		}
	}
	var lengths [gcmBlockSize]byte
	byteorder.BEPutUint64(lengths[:8], uint64(len(data))*8)
	byteorder.BEPutUint64(lengths[8:], uint64(len(ciphertext))*8)
	cop2GHASH(h, &state, &lengths[0], 1)
	byteorder.BEPutUint64(tag[:8], state[0]^tagMask[0])
	byteorder.BEPutUint64(tag[8:], state[1]^tagMask[1])
	return tag
}
