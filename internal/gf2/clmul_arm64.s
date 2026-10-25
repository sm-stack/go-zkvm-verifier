//go:build arm64 && !purego

#include "textflag.h"

// REDUCE folds the 128-bit product (hi, lo) modulo x^64 + x^4 + x^3 + x + 1 into lo. Clobbers R10, R11.
#define REDUCE(hi, lo) \
	EOR	hi, lo, lo; \
	EOR	hi<<1, lo, lo; \
	EOR	hi<<3, lo, lo; \
	EOR	hi<<4, lo, lo; \
	LSR	$63, hi, R10; \
	EOR	hi>>61, R10, R10; \
	EOR	hi>>60, R10, R10; \
	EOR	R10, lo, lo; \
	EOR	R10<<1, lo, lo; \
	EOR	R10<<3, lo, lo; \
	EOR	R10<<4, lo, lo

// func kmulPMULL(a, b uint64) uint64
TEXT ·kmulPMULL(SB), NOSPLIT, $0-24
	MOVD	a+0(FP), R0
	MOVD	b+8(FP), R1
	VMOV	R0, V0.D[0]
	VMOV	R1, V1.D[0]
	VPMULL	V0.D1, V1.D1, V2.Q1
	VMOV	V2.D[0], R2
	VMOV	V2.D[1], R3
	REDUCE(R3, R2)
	MOVD	R2, ret+16(FP)
	RET

// func extMulPMULL(a0, a1, a2, b0, b1, b2 uint64) (c0, c1, c2 uint64)
TEXT ·extMulPMULL(SB), NOSPLIT, $0-72
	MOVD	a0+0(FP), R0
	MOVD	a1+8(FP), R1
	MOVD	a2+16(FP), R2
	MOVD	b0+24(FP), R3
	MOVD	b1+32(FP), R4
	MOVD	b2+40(FP), R5
	VMOV	R0, V0.D[0]
	VMOV	R1, V1.D[0]
	VMOV	R2, V2.D[0]
	VMOV	R3, V3.D[0]
	VMOV	R4, V4.D[0]
	VMOV	R5, V5.D[0]
	EOR	R0, R1, R6
	EOR	R3, R4, R7
	VMOV	R6, V6.D[0]
	VMOV	R7, V7.D[0]
	EOR	R0, R2, R6
	EOR	R3, R5, R7
	VMOV	R6, V8.D[0]
	VMOV	R7, V9.D[0]
	EOR	R1, R2, R6
	EOR	R4, R5, R7
	VMOV	R6, V10.D[0]
	VMOV	R7, V11.D[0]
	VPMULL	V0.D1, V3.D1, V12.Q1   // P00
	VPMULL	V1.D1, V4.D1, V13.Q1   // P11
	VPMULL	V2.D1, V5.D1, V14.Q1   // P22
	VPMULL	V6.D1, V7.D1, V15.Q1   // P01
	VPMULL	V8.D1, V9.D1, V16.Q1   // P02
	VPMULL	V10.D1, V11.D1, V17.Q1 // P12
	// p1 = P01^P00^P11, p2 = P02^P00^P22^P11, p3 = P12^P11^P22
	VEOR	V12.B16, V13.B16, V18.B16 // P00^P11
	VEOR	V15.B16, V18.B16, V19.B16 // p1
	VEOR	V16.B16, V18.B16, V20.B16
	VEOR	V14.B16, V20.B16, V20.B16 // p2
	VEOR	V13.B16, V14.B16, V21.B16
	VEOR	V17.B16, V21.B16, V21.B16 // p3
	VEOR	V12.B16, V21.B16, V22.B16 // c0 = P00^p3
	VEOR	V19.B16, V21.B16, V23.B16
	VEOR	V14.B16, V23.B16, V23.B16 // c1 = p1^p3^P22
	VEOR	V20.B16, V14.B16, V24.B16 // c2 = p2^P22
	VMOV	V22.D[0], R0
	VMOV	V22.D[1], R1
	REDUCE(R1, R0)
	VMOV	V23.D[0], R2
	VMOV	V23.D[1], R3
	REDUCE(R3, R2)
	VMOV	V24.D[0], R4
	VMOV	V24.D[1], R5
	REDUCE(R5, R4)
	MOVD	R0, c0+48(FP)
	MOVD	R2, c1+56(FP)
	MOVD	R4, c2+64(FP)
	RET
