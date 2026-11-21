// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

#include "textflag.h"
#include "funcdata.h"

// The Go MIPS assembler does not have COP2 mnemonics. These are OCTEON's
// 16-bit selectors, as named in the Cavium cvmx-asm.h AES and GFM macros.
#define DMTC2(rt, selector) WORD $(0x48a00000 | ((rt) << 16) | (selector))
#define DMFC2(rt, selector) WORD $(0x48200000 | ((rt) << 16) | (selector))
// Paired big-endian unaligned memory operations. For an eight-byte word,
// the left instruction addresses its first byte and the right its last.
#define LDL(rt, base, off) WORD $(0x68000000 | ((base) << 21) | ((rt) << 16) | (off))
#define LDR(rt, base, off) WORD $(0x6c000000 | ((base) << 21) | ((rt) << 16) | (off))
#define SDL(rt, base, off) WORD $(0xb0000000 | ((base) << 21) | ((rt) << 16) | (off))
#define SDR(rt, base, off) WORD $(0xb4000000 | ((base) << 21) | ((rt) << 16) | (off))
#define AES_KEY0       0x0104
#define AES_KEYLEN     0x0110
#define AES_ENC0       0x010a
#define AES_ENC1       0x310b
#define AES_RESULT0    0x0100
#define GFM_POLY       0x025e
#define GFM_MUL0       0x0258
#define GFM_RESINP0    0x025a
#define GFM_XOR0       0x025c
#define GFM_XORMUL1    0x425d

// Each leaf receives 1..cop2Batch aligned blocks, loads all its own COP2
// state, and writes its results back before returning. Linux saves COP2
// on OS thread switches, but Go does not save it on goroutine switches.
// PCDATA_UnsafePoint=-2 excludes async preemption while state is live.
TEXT ·cop2AES(SB), NOSPLIT|NOFRAME, $0-32
	PCDATA $PCDATA_UnsafePoint, $-2
	MOVV key+0(FP), R1
	MOVV keyLen+8(FP), R2
	MOVV blocks+16(FP), R3
	MOVV n+24(FP), R4
	MOVV 0(R1), R8
	MOVV 8(R1), R9
	MOVV 16(R1), R10
	MOVV 24(R1), R11
	DMTC2(8, AES_KEY0)
	DMTC2(9, AES_KEY0+1)
	DMTC2(10, AES_KEY0+2)
	DMTC2(11, AES_KEY0+3)
	DMTC2(2, AES_KEYLEN)
aesloop:
	MOVV 0(R3), R8
	MOVV 8(R3), R9
	DMTC2(8, AES_ENC0)
	DMTC2(9, AES_ENC1)
	DMFC2(8, AES_RESULT0)
	DMFC2(9, AES_RESULT0+1)
	MOVV R8, 0(R3)
	MOVV R9, 8(R3)
	ADDV $16, R3
	ADDV $-1, R4
	BNE R4, aesloop
	RET

TEXT ·cop2GHASH(SB), NOSPLIT|NOFRAME, $0-32
	PCDATA $PCDATA_UnsafePoint, $-2
	MOVV h+0(FP), R1
	MOVV state+8(FP), R2
	MOVV blocks+16(FP), R3
	MOVV n+24(FP), R4
	MOVV $0xe100, R8 // GHASH polynomial in OCTEON's unreflected mode.
	DMTC2(8, GFM_POLY)
	MOVV 0(R1), R8
	MOVV 8(R1), R9
	DMTC2(8, GFM_MUL0)
	DMTC2(9, GFM_MUL0+1)
	MOVV 0(R2), R8
	MOVV 8(R2), R9
	DMTC2(8, GFM_RESINP0)
	DMTC2(9, GFM_RESINP0+1)
ghashloop:
	LDL(8, 3, 0)
	LDR(8, 3, 7)
	LDL(9, 3, 8)
	LDR(9, 3, 15)
	DMTC2(8, GFM_XOR0)
	DMTC2(9, GFM_XORMUL1)
	ADDV $16, R3
	ADDV $-1, R4
	BNE R4, ghashloop
	DMFC2(8, GFM_RESINP0)
	DMFC2(9, GFM_RESINP0+1)
	MOVV R8, 0(R2)
	MOVV R9, 8(R2)
	RET

TEXT ·cop2CTR(SB), NOSPLIT|NOFRAME, $0-64
	PCDATA $PCDATA_UnsafePoint, $-2
	MOVV key+0(FP), R1
	MOVV keyLen+8(FP), R2
	MOVV dst+16(FP), R3
	MOVV src+24(FP), R4
	MOVV n+32(FP), R5
	MOVV hi+40(FP), R6
	MOVV prefix+48(FP), R7
	MOVV ctr+56(FP), R12
	MOVV $0xffffffff, R13
	MOVV 0(R1), R8
	MOVV 8(R1), R9
	MOVV 16(R1), R10
	MOVV 24(R1), R11
	DMTC2(8, AES_KEY0)
	DMTC2(9, AES_KEY0+1)
	DMTC2(10, AES_KEY0+2)
	DMTC2(11, AES_KEY0+3)
	DMTC2(2, AES_KEYLEN)
ctrloop:
	OR R7, R12, R14
	DMTC2(6, AES_ENC0)
	DMTC2(14, AES_ENC1)
	LDL(10, 4, 0)
	LDR(10, 4, 7)
	LDL(11, 4, 8)
	LDR(11, 4, 15)
	DMFC2(8, AES_RESULT0)
	DMFC2(9, AES_RESULT0+1)
	XOR R10, R8
	XOR R11, R9
	SDL(8, 3, 0)
	SDR(8, 3, 7)
	SDL(9, 3, 8)
	SDR(9, 3, 15)
	ADDVU $1, R12
	AND R13, R12
	ADDVU $16, R3
	ADDVU $16, R4
	ADDVU $-1, R5
	BNE R5, ctrloop
	RET
