// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build octeoncop2 && !purego

#include "textflag.h"
#include "funcdata.h"

#define DMTC2(rt, selector) WORD $(0x48a00000 | ((rt) << 16) | (selector))
#define DMFC2(rt, selector) WORD $(0x48200000 | ((rt) << 16) | (selector))
#define HSH_DATA_WIDE 0x0240
#define HSH_STATE_WIDE 0x0250
#define HSH_SHA512 0x424f

// Big-endian paired loads for an eight-byte word at arbitrary alignment.
#define LDL8(off) WORD $(0x68480000 | (off)) // LDL R8, off(R2)
#define LDR8(off) WORD $(0x6c480000 | (off)) // LDR R8, off(R2)
#define LOAD_STATE(i) \
	MOVV (8*i)(R1), R8; \
	DMTC2(8, HSH_STATE_WIDE+i)
#define SAVE_STATE(i) \
	DMFC2(8, HSH_STATE_WIDE+i); \
	MOVV R8, (8*i)(R1)
#define LOAD_DATA(i) \
	LDL8(8*i); \
	LDR8(8*i+7); \
	DMTC2(8, HSH_DATA_WIDE+i)

// The bounded leaf never keeps chaining state in COP2 across Go calls.
TEXT ·blockOcteon(SB), NOSPLIT|NOFRAME, $0-24
	PCDATA $PCDATA_UnsafePoint, $-2
	MOVV state+0(FP), R1
	MOVV input+8(FP), R2
	MOVV n+16(FP), R3
	LOAD_STATE(0)
	LOAD_STATE(1)
	LOAD_STATE(2)
	LOAD_STATE(3)
	LOAD_STATE(4)
	LOAD_STATE(5)
	LOAD_STATE(6)
	LOAD_STATE(7)
loop:
	LOAD_DATA(0)
	LOAD_DATA(1)
	LOAD_DATA(2)
	LOAD_DATA(3)
	LOAD_DATA(4)
	LOAD_DATA(5)
	LOAD_DATA(6)
	LOAD_DATA(7)
	LOAD_DATA(8)
	LOAD_DATA(9)
	LOAD_DATA(10)
	LOAD_DATA(11)
	LOAD_DATA(12)
	LOAD_DATA(13)
	LOAD_DATA(14)
	LDL8(120)
	LDR8(127)
	// Synchronize with the previous compression before triggering this one.
	DMFC2(0, HSH_STATE_WIDE)
	DMTC2(8, HSH_SHA512)
	ADDVU $128, R2
	ADDVU $-1, R3
	BNE R3, loop
	SAVE_STATE(0)
	SAVE_STATE(1)
	SAVE_STATE(2)
	SAVE_STATE(3)
	SAVE_STATE(4)
	SAVE_STATE(5)
	SAVE_STATE(6)
	SAVE_STATE(7)
	RET
