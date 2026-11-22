// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

#include "textflag.h"
#include "funcdata.h"

#define DMTC2(rt, selector) WORD $(0x48a00000 | ((rt) << 16) | (selector))
#define DMFC2(rt, selector) WORD $(0x48200000 | ((rt) << 16) | (selector))
#define HSH_DATA 0x0040
#define HSH_STATE 0x0048
#define HSH_STATE_WIDE 0x0250
#define HSH_SHA256 0x404f

// Load exactly eight bytes of a possibly unaligned big-endian input.
#define LDL8(off) WORD $(0x68480000 | (off)) // LDL R8, off(R2)
#define LDR8(off) WORD $(0x6c480000 | (off)) // LDR R8, off(R2)

// The Go chaining state is only uint32-aligned. Pack and unpack it in
// pairs rather than loading 64-bit words from state.
#define LOAD_STATE(i) \
	MOVWU (8*i)(R1), R8; \
	MOVWU (8*i+4)(R1), R9; \
	SLLV $32, R8; \
	OR R9, R8; \
	DMTC2(8, HSH_STATE+i)
#define SAVE_STATE(i) \
	DMFC2(8, HSH_STATE+i); \
	SRLV $32, R8, R9; \
	MOVW R9, (8*i)(R1); \
	MOVW R8, (8*i+4)(R1)
#define LOAD_DATA(i) \
	LDL8(8*i); \
	LDR8(8*i+7); \
	DMTC2(8, HSH_DATA+i)

// State is live in COP2 only in this bounded leaf. Linux preserves COP2
// across OS thread switches; Go must not asynchronously preempt this leaf.
TEXT ·blockOcteon(SB), NOSPLIT|NOFRAME, $0-24
	PCDATA $PCDATA_UnsafePoint, $-2
	MOVV state+0(FP), R1
	MOVV input+8(FP), R2
	MOVV n+16(FP), R3
	LOAD_STATE(0)
	LOAD_STATE(1)
	LOAD_STATE(2)
	LOAD_STATE(3)
loop:
	LOAD_DATA(0)
	LOAD_DATA(1)
	LOAD_DATA(2)
	LOAD_DATA(3)
	LOAD_DATA(4)
	LOAD_DATA(5)
	LOAD_DATA(6)
	LDL8(56)
	LDR8(63)
	// Synchronize with the previous compression before triggering this one.
	DMFC2(0, HSH_STATE_WIDE)
	DMTC2(8, HSH_SHA256)
	ADDVU $64, R2
	ADDVU $-1, R3
	BNE R3, loop
	SAVE_STATE(0)
	SAVE_STATE(1)
	SAVE_STATE(2)
	SAVE_STATE(3)
	RET
