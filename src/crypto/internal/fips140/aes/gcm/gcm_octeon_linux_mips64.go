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
)

func checkGenericIsExpected() {}

// Initialized once and read-only after New. No COP2 register state is
// assumed to survive between calls.
type gcmPlatformData struct {
	key    [4]uint64
	keyLen uint64 // zero selects the generic implementation
	h      cop2Block
}

func initGCM(g *GCM) {
	if fips140.Enabled || g.nonceSize != gcmStandardNonceSize || g.tagSize != gcmTagSize {
		return
	}
	if n, ok := aes.COP2Key(&g.cipher, &g.key); ok {
		g.keyLen = n
		cop2AES(&g.key, n, &g.h, 1) // H = AES_K(0).
	}
}

// Batch blocks both to amortize setup and to bound the async-unsafe region.
const cop2Batch = 128 // 2 KiB per assembly call.

type cop2Block [2]uint64

//go:noescape
func cop2AES(key *[4]uint64, keyLen uint64, blocks *cop2Block, n int)

//go:noescape
func cop2GHASH(h, state *cop2Block, blocks *byte, n int)

//go:noescape
func cop2CTR(key *[4]uint64, keyLen uint64, dst, src *byte, n int, hi, prefix, ctr uint64)

//go:noescape
func cop2SealBlocks(key *[4]uint64, keyLen uint64, dst, src *byte, n int, hi, prefix, ctr uint64, h, state *cop2Block)

func seal(out []byte, g *GCM, nonce, plaintext, data []byte) {
	if g.keyLen == 0 {
		sealGeneric(out, g, nonce, plaintext, data)
		return
	}

	j0, tagMask := g.cop2Init(nonce)
	ciphertext := out[:len(plaintext)]
	var state cop2Block
	cop2HashInput(&g.h, &state, data)
	prefix, ctr := j0[1]&^0xffffffff, uint32(j0[1])+1
	in, dst := plaintext, ciphertext
	for len(in) >= gcmBlockSize {
		n := min(cop2Batch, len(in)/gcmBlockSize)
		cop2SealBlocks(&g.key, g.keyLen, &dst[0], &in[0], n, j0[0], prefix, uint64(ctr), &g.h, &state)
		ctr += uint32(n)
		in, dst = in[n*gcmBlockSize:], dst[n*gcmBlockSize:]
	}
	if len(in) != 0 {
		cop2CryptTail(&g.key, g.keyLen, cop2Block{j0[0], prefix | uint64(ctr)}, dst, in)
		cop2HashInput(&g.h, &state, dst)
	}
	tag := cop2Tag(&g.h, &state, tagMask, len(ciphertext), len(data))
	copy(out[len(plaintext):], tag[:])
}

func open(out []byte, g *GCM, nonce, ciphertext, data []byte) error {
	if g.keyLen == 0 {
		return openGeneric(out, g, nonce, ciphertext, data)
	}

	j0, tagMask := g.cop2Init(nonce)
	n := len(ciphertext) - gcmTagSize
	tag := cop2Auth(&g.h, tagMask, ciphertext[:n], data)
	if subtle.ConstantTimeCompare(tag[:], ciphertext[n:]) != 1 {
		return errOpen
	}
	cop2Crypt(&g.key, g.keyLen, j0, out, ciphertext[:n])
	return nil
}

// The standard 96-bit nonce is followed by a 32-bit counter. J0 has counter
// value one; the first payload block uses counter value two.
func (g *GCM) cop2Init(nonce []byte) (j0, tagMask cop2Block) {
	j0 = cop2Block{byteorder.BEUint64(nonce), uint64(byteorder.BEUint32(nonce[8:]))<<32 | 1}
	tagMask = j0
	cop2AES(&g.key, g.keyLen, &tagMask, 1)
	return j0, tagMask
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
		cop2CryptTail(key, keyLen, cop2Block{j0[0], prefix | uint64(ctr)}, out, in)
	}
}

func cop2CryptTail(key *[4]uint64, keyLen uint64, counter cop2Block, out, in []byte) {
	cop2AES(key, keyLen, &counter, 1)
	var mask [gcmBlockSize]byte
	byteorder.BEPutUint64(mask[:8], counter[0])
	byteorder.BEPutUint64(mask[8:], counter[1])
	subtle.XORBytes(out, in, mask[:len(in)])
}

// cop2HashInput hashes an independently zero-padded input.
func cop2HashInput(h, state *cop2Block, input []byte) {
	for len(input) >= gcmBlockSize {
		n := min(cop2Batch, len(input)/gcmBlockSize)
		cop2GHASH(h, state, &input[0], n)
		input = input[n*gcmBlockSize:]
	}
	if len(input) != 0 {
		var tail [gcmBlockSize]byte
		copy(tail[:], input)
		cop2GHASH(h, state, &tail[0], 1)
	}
}

func cop2Auth(h *cop2Block, tagMask cop2Block, ciphertext, data []byte) [gcmTagSize]byte {
	var state cop2Block
	cop2HashInput(h, &state, data)
	cop2HashInput(h, &state, ciphertext)
	return cop2Tag(h, &state, tagMask, len(ciphertext), len(data))
}

func cop2Tag(h, state *cop2Block, tagMask cop2Block, ciphertextLen, dataLen int) (tag [gcmTagSize]byte) {
	var lengths [gcmBlockSize]byte
	byteorder.BEPutUint64(lengths[:8], uint64(dataLen)*8)
	byteorder.BEPutUint64(lengths[8:], uint64(ciphertextLen)*8)
	cop2GHASH(h, state, &lengths[0], 1)
	byteorder.BEPutUint64(tag[:8], state[0]^tagMask[0])
	byteorder.BEPutUint64(tag[8:], state[1]^tagMask[1])
	return tag
}
