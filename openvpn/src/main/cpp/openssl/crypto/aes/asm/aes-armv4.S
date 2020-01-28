@ Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
@
@ Licensed under the OpenSSL license (the "License").  You may not use
@ this file except in compliance with the License.  You can obtain a copy
@ in the file LICENSE in the source distribution or at
@ https://www.openssl.org/source/license.html


@ ====================================================================
@ Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
@ project. The module is, however, dual licensed under OpenSSL and
@ CRYPTOGAMS licenses depending on where you obtain it. For further
@ details see http://www.openssl.org/~appro/cryptogams/.
@ ====================================================================

@ AES for ARMv4

@ January 2007.
@
@ Code uses single 1K S-box and is >2 times faster than code generated
@ by gcc-3.4.1. This is thanks to unique feature of ARMv4 ISA, which
@ allows to merge logical or arithmetic operation with shift or rotate
@ in one instruction and emit combined result every cycle. The module
@ is endian-neutral. The performance is ~42 cycles/byte for 128-bit
@ key [on single-issue Xscale PXA250 core].

@ May 2007.
@
@ AES_set_[en|de]crypt_key is added.

@ July 2010.
@
@ Rescheduling for dual-issue pipeline resulted in 12% improvement on
@ Cortex A8 core and ~25 cycles per byte processed with 128-bit key.

@ February 2011.
@
@ Profiler-assisted and platform-specific optimization resulted in 16%
@ improvement on Cortex A8 core and ~21.5 cycles per byte.

#ifndef __KERNEL__
# include "arm_arch.h"
#else
# define __ARM_ARCH__ __LINUX_ARM_ARCH__
#endif

.text
#if defined(__thumb2__) && !defined(__APPLE__)
.syntax	unified
.thumb
#else
.code	32
#undef __thumb2__
#endif

.type	AES_Te,%object
.align	5
AES_Te:
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
@ Te4[256]
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
@ rcon[]
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0, 0, 0, 0, 0, 0
.size	AES_Te,.-AES_Te

@ void AES_encrypt(const unsigned char *in, unsigned char *out,
@ 		 const AES_KEY *key) {
.global AES_encrypt
.type   AES_encrypt,%function
.align	5
AES_encrypt:
#ifndef	__thumb2__
	sub	r3,pc,#8		@ AES_encrypt
#else
	adr	r3,.
#endif
	stmdb   sp!,{r1,r4-r12,lr}
#if defined(__thumb2__) || defined(__APPLE__)
	adr	r10,AES_Te
#else
	sub	r10,r3,#AES_encrypt-AES_Te	@ Te
#endif
	mov	r12,r0		@ inp
	mov	r11,r2
#if __ARM_ARCH__<7
	ldrb	r0,[r12,#3]	@ load input data in endian-neutral
	ldrb	r4,[r12,#2]	@ manner...
	ldrb	r5,[r12,#1]
	ldrb	r6,[r12,#0]
	orr	r0,r0,r4,lsl#8
	ldrb	r1,[r12,#7]
	orr	r0,r0,r5,lsl#16
	ldrb	r4,[r12,#6]
	orr	r0,r0,r6,lsl#24
	ldrb	r5,[r12,#5]
	ldrb	r6,[r12,#4]
	orr	r1,r1,r4,lsl#8
	ldrb	r2,[r12,#11]
	orr	r1,r1,r5,lsl#16
	ldrb	r4,[r12,#10]
	orr	r1,r1,r6,lsl#24
	ldrb	r5,[r12,#9]
	ldrb	r6,[r12,#8]
	orr	r2,r2,r4,lsl#8
	ldrb	r3,[r12,#15]
	orr	r2,r2,r5,lsl#16
	ldrb	r4,[r12,#14]
	orr	r2,r2,r6,lsl#24
	ldrb	r5,[r12,#13]
	ldrb	r6,[r12,#12]
	orr	r3,r3,r4,lsl#8
	orr	r3,r3,r5,lsl#16
	orr	r3,r3,r6,lsl#24
#else
	ldr	r0,[r12,#0]
	ldr	r1,[r12,#4]
	ldr	r2,[r12,#8]
	ldr	r3,[r12,#12]
#ifdef __ARMEL__
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
#endif
	bl	_armv4_AES_encrypt

	ldr	r12,[sp],#4		@ pop out
#if __ARM_ARCH__>=7
#ifdef __ARMEL__
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
	str	r0,[r12,#0]
	str	r1,[r12,#4]
	str	r2,[r12,#8]
	str	r3,[r12,#12]
#else
	mov	r4,r0,lsr#24		@ write output in endian-neutral
	mov	r5,r0,lsr#16		@ manner...
	mov	r6,r0,lsr#8
	strb	r4,[r12,#0]
	strb	r5,[r12,#1]
	mov	r4,r1,lsr#24
	strb	r6,[r12,#2]
	mov	r5,r1,lsr#16
	strb	r0,[r12,#3]
	mov	r6,r1,lsr#8
	strb	r4,[r12,#4]
	strb	r5,[r12,#5]
	mov	r4,r2,lsr#24
	strb	r6,[r12,#6]
	mov	r5,r2,lsr#16
	strb	r1,[r12,#7]
	mov	r6,r2,lsr#8
	strb	r4,[r12,#8]
	strb	r5,[r12,#9]
	mov	r4,r3,lsr#24
	strb	r6,[r12,#10]
	mov	r5,r3,lsr#16
	strb	r2,[r12,#11]
	mov	r6,r3,lsr#8
	strb	r4,[r12,#12]
	strb	r5,[r12,#13]
	strb	r6,[r12,#14]
	strb	r3,[r12,#15]
#endif
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	.word	0xFF			@ interoperable with Thumb ISA:-)
#endif
.size	AES_encrypt,.-AES_encrypt

.type   _armv4_AES_encrypt,%function
.align	2
_armv4_AES_encrypt:
	str	lr,[sp,#-4]!		@ push lr
	ldmia	r11!,{r4-r7}
	eor	r0,r0,r4
	ldr	r12,[r11,#240-16]
	eor	r1,r1,r5
	eor	r2,r2,r6
	eor	r3,r3,r7
	sub	r12,r12,#1
	mov	lr,#255

	and	r7,lr,r0
	and	r8,lr,r0,lsr#8
	and	r9,lr,r0,lsr#16
	mov	r0,r0,lsr#24
.Lenc_loop:
	ldr	r4,[r10,r7,lsl#2]	@ Te3[s0>>0]
	and	r7,lr,r1,lsr#16	@ i0
	ldr	r5,[r10,r8,lsl#2]	@ Te2[s0>>8]
	and	r8,lr,r1
	ldr	r6,[r10,r9,lsl#2]	@ Te1[s0>>16]
	and	r9,lr,r1,lsr#8
	ldr	r0,[r10,r0,lsl#2]	@ Te0[s0>>24]
	mov	r1,r1,lsr#24

	ldr	r7,[r10,r7,lsl#2]	@ Te1[s1>>16]
	ldr	r8,[r10,r8,lsl#2]	@ Te3[s1>>0]
	ldr	r9,[r10,r9,lsl#2]	@ Te2[s1>>8]
	eor	r0,r0,r7,ror#8
	ldr	r1,[r10,r1,lsl#2]	@ Te0[s1>>24]
	and	r7,lr,r2,lsr#8	@ i0
	eor	r5,r5,r8,ror#8
	and	r8,lr,r2,lsr#16	@ i1
	eor	r6,r6,r9,ror#8
	and	r9,lr,r2
	ldr	r7,[r10,r7,lsl#2]	@ Te2[s2>>8]
	eor	r1,r1,r4,ror#24
	ldr	r8,[r10,r8,lsl#2]	@ Te1[s2>>16]
	mov	r2,r2,lsr#24

	ldr	r9,[r10,r9,lsl#2]	@ Te3[s2>>0]
	eor	r0,r0,r7,ror#16
	ldr	r2,[r10,r2,lsl#2]	@ Te0[s2>>24]
	and	r7,lr,r3		@ i0
	eor	r1,r1,r8,ror#8
	and	r8,lr,r3,lsr#8	@ i1
	eor	r6,r6,r9,ror#16
	and	r9,lr,r3,lsr#16	@ i2
	ldr	r7,[r10,r7,lsl#2]	@ Te3[s3>>0]
	eor	r2,r2,r5,ror#16
	ldr	r8,[r10,r8,lsl#2]	@ Te2[s3>>8]
	mov	r3,r3,lsr#24

	ldr	r9,[r10,r9,lsl#2]	@ Te1[s3>>16]
	eor	r0,r0,r7,ror#24
	ldr	r7,[r11],#16
	eor	r1,r1,r8,ror#16
	ldr	r3,[r10,r3,lsl#2]	@ Te0[s3>>24]
	eor	r2,r2,r9,ror#8
	ldr	r4,[r11,#-12]
	eor	r3,r3,r6,ror#8

	ldr	r5,[r11,#-8]
	eor	r0,r0,r7
	ldr	r6,[r11,#-4]
	and	r7,lr,r0
	eor	r1,r1,r4
	and	r8,lr,r0,lsr#8
	eor	r2,r2,r5
	and	r9,lr,r0,lsr#16
	eor	r3,r3,r6
	mov	r0,r0,lsr#24

	subs	r12,r12,#1
	bne	.Lenc_loop

	add	r10,r10,#2

	ldrb	r4,[r10,r7,lsl#2]	@ Te4[s0>>0]
	and	r7,lr,r1,lsr#16	@ i0
	ldrb	r5,[r10,r8,lsl#2]	@ Te4[s0>>8]
	and	r8,lr,r1
	ldrb	r6,[r10,r9,lsl#2]	@ Te4[s0>>16]
	and	r9,lr,r1,lsr#8
	ldrb	r0,[r10,r0,lsl#2]	@ Te4[s0>>24]
	mov	r1,r1,lsr#24

	ldrb	r7,[r10,r7,lsl#2]	@ Te4[s1>>16]
	ldrb	r8,[r10,r8,lsl#2]	@ Te4[s1>>0]
	ldrb	r9,[r10,r9,lsl#2]	@ Te4[s1>>8]
	eor	r0,r7,r0,lsl#8
	ldrb	r1,[r10,r1,lsl#2]	@ Te4[s1>>24]
	and	r7,lr,r2,lsr#8	@ i0
	eor	r5,r8,r5,lsl#8
	and	r8,lr,r2,lsr#16	@ i1
	eor	r6,r9,r6,lsl#8
	and	r9,lr,r2
	ldrb	r7,[r10,r7,lsl#2]	@ Te4[s2>>8]
	eor	r1,r4,r1,lsl#24
	ldrb	r8,[r10,r8,lsl#2]	@ Te4[s2>>16]
	mov	r2,r2,lsr#24

	ldrb	r9,[r10,r9,lsl#2]	@ Te4[s2>>0]
	eor	r0,r7,r0,lsl#8
	ldrb	r2,[r10,r2,lsl#2]	@ Te4[s2>>24]
	and	r7,lr,r3		@ i0
	eor	r1,r1,r8,lsl#16
	and	r8,lr,r3,lsr#8	@ i1
	eor	r6,r9,r6,lsl#8
	and	r9,lr,r3,lsr#16	@ i2
	ldrb	r7,[r10,r7,lsl#2]	@ Te4[s3>>0]
	eor	r2,r5,r2,lsl#24
	ldrb	r8,[r10,r8,lsl#2]	@ Te4[s3>>8]
	mov	r3,r3,lsr#24

	ldrb	r9,[r10,r9,lsl#2]	@ Te4[s3>>16]
	eor	r0,r7,r0,lsl#8
	ldr	r7,[r11,#0]
	ldrb	r3,[r10,r3,lsl#2]	@ Te4[s3>>24]
	eor	r1,r1,r8,lsl#8
	ldr	r4,[r11,#4]
	eor	r2,r2,r9,lsl#16
	ldr	r5,[r11,#8]
	eor	r3,r6,r3,lsl#24
	ldr	r6,[r11,#12]

	eor	r0,r0,r7
	eor	r1,r1,r4
	eor	r2,r2,r5
	eor	r3,r3,r6

	sub	r10,r10,#2
	ldr	pc,[sp],#4		@ pop and return
.size	_armv4_AES_encrypt,.-_armv4_AES_encrypt

.global AES_set_encrypt_key
.type   AES_set_encrypt_key,%function
.align	5
AES_set_encrypt_key:
_armv4_AES_set_encrypt_key:
#ifndef	__thumb2__
	sub	r3,pc,#8		@ AES_set_encrypt_key
#else
	adr	r3,.
#endif
	teq	r0,#0
#ifdef	__thumb2__
	itt	eq			@ Thumb2 thing, sanity check in ARM
#endif
	moveq	r0,#-1
	beq	.Labrt
	teq	r2,#0
#ifdef	__thumb2__
	itt	eq			@ Thumb2 thing, sanity check in ARM
#endif
	moveq	r0,#-1
	beq	.Labrt

	teq	r1,#128
	beq	.Lok
	teq	r1,#192
	beq	.Lok
	teq	r1,#256
#ifdef	__thumb2__
	itt	ne			@ Thumb2 thing, sanity check in ARM
#endif
	movne	r0,#-1
	bne	.Labrt

.Lok:	stmdb   sp!,{r4-r12,lr}
	mov	r12,r0		@ inp
	mov	lr,r1			@ bits
	mov	r11,r2			@ key

#if defined(__thumb2__) || defined(__APPLE__)
	adr	r10,AES_Te+1024				@ Te4
#else
	sub	r10,r3,#_armv4_AES_set_encrypt_key-AES_Te-1024	@ Te4
#endif

#if __ARM_ARCH__<7
	ldrb	r0,[r12,#3]	@ load input data in endian-neutral
	ldrb	r4,[r12,#2]	@ manner...
	ldrb	r5,[r12,#1]
	ldrb	r6,[r12,#0]
	orr	r0,r0,r4,lsl#8
	ldrb	r1,[r12,#7]
	orr	r0,r0,r5,lsl#16
	ldrb	r4,[r12,#6]
	orr	r0,r0,r6,lsl#24
	ldrb	r5,[r12,#5]
	ldrb	r6,[r12,#4]
	orr	r1,r1,r4,lsl#8
	ldrb	r2,[r12,#11]
	orr	r1,r1,r5,lsl#16
	ldrb	r4,[r12,#10]
	orr	r1,r1,r6,lsl#24
	ldrb	r5,[r12,#9]
	ldrb	r6,[r12,#8]
	orr	r2,r2,r4,lsl#8
	ldrb	r3,[r12,#15]
	orr	r2,r2,r5,lsl#16
	ldrb	r4,[r12,#14]
	orr	r2,r2,r6,lsl#24
	ldrb	r5,[r12,#13]
	ldrb	r6,[r12,#12]
	orr	r3,r3,r4,lsl#8
	str	r0,[r11],#16
	orr	r3,r3,r5,lsl#16
	str	r1,[r11,#-12]
	orr	r3,r3,r6,lsl#24
	str	r2,[r11,#-8]
	str	r3,[r11,#-4]
#else
	ldr	r0,[r12,#0]
	ldr	r1,[r12,#4]
	ldr	r2,[r12,#8]
	ldr	r3,[r12,#12]
#ifdef __ARMEL__
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
	str	r0,[r11],#16
	str	r1,[r11,#-12]
	str	r2,[r11,#-8]
	str	r3,[r11,#-4]
#endif

	teq	lr,#128
	bne	.Lnot128
	mov	r12,#10
	str	r12,[r11,#240-16]
	add	r6,r10,#256			@ rcon
	mov	lr,#255

.L128_loop:
	and	r5,lr,r3,lsr#24
	and	r7,lr,r3,lsr#16
	ldrb	r5,[r10,r5]
	and	r8,lr,r3,lsr#8
	ldrb	r7,[r10,r7]
	and	r9,lr,r3
	ldrb	r8,[r10,r8]
	orr	r5,r5,r7,lsl#24
	ldrb	r9,[r10,r9]
	orr	r5,r5,r8,lsl#16
	ldr	r4,[r6],#4			@ rcon[i++]
	orr	r5,r5,r9,lsl#8
	eor	r5,r5,r4
	eor	r0,r0,r5			@ rk[4]=rk[0]^...
	eor	r1,r1,r0			@ rk[5]=rk[1]^rk[4]
	str	r0,[r11],#16
	eor	r2,r2,r1			@ rk[6]=rk[2]^rk[5]
	str	r1,[r11,#-12]
	eor	r3,r3,r2			@ rk[7]=rk[3]^rk[6]
	str	r2,[r11,#-8]
	subs	r12,r12,#1
	str	r3,[r11,#-4]
	bne	.L128_loop
	sub	r2,r11,#176
	b	.Ldone

.Lnot128:
#if __ARM_ARCH__<7
	ldrb	r8,[r12,#19]
	ldrb	r4,[r12,#18]
	ldrb	r5,[r12,#17]
	ldrb	r6,[r12,#16]
	orr	r8,r8,r4,lsl#8
	ldrb	r9,[r12,#23]
	orr	r8,r8,r5,lsl#16
	ldrb	r4,[r12,#22]
	orr	r8,r8,r6,lsl#24
	ldrb	r5,[r12,#21]
	ldrb	r6,[r12,#20]
	orr	r9,r9,r4,lsl#8
	orr	r9,r9,r5,lsl#16
	str	r8,[r11],#8
	orr	r9,r9,r6,lsl#24
	str	r9,[r11,#-4]
#else
	ldr	r8,[r12,#16]
	ldr	r9,[r12,#20]
#ifdef __ARMEL__
	rev	r8,r8
	rev	r9,r9
#endif
	str	r8,[r11],#8
	str	r9,[r11,#-4]
#endif

	teq	lr,#192
	bne	.Lnot192
	mov	r12,#12
	str	r12,[r11,#240-24]
	add	r6,r10,#256			@ rcon
	mov	lr,#255
	mov	r12,#8

.L192_loop:
	and	r5,lr,r9,lsr#24
	and	r7,lr,r9,lsr#16
	ldrb	r5,[r10,r5]
	and	r8,lr,r9,lsr#8
	ldrb	r7,[r10,r7]
	and	r9,lr,r9
	ldrb	r8,[r10,r8]
	orr	r5,r5,r7,lsl#24
	ldrb	r9,[r10,r9]
	orr	r5,r5,r8,lsl#16
	ldr	r4,[r6],#4			@ rcon[i++]
	orr	r5,r5,r9,lsl#8
	eor	r9,r5,r4
	eor	r0,r0,r9			@ rk[6]=rk[0]^...
	eor	r1,r1,r0			@ rk[7]=rk[1]^rk[6]
	str	r0,[r11],#24
	eor	r2,r2,r1			@ rk[8]=rk[2]^rk[7]
	str	r1,[r11,#-20]
	eor	r3,r3,r2			@ rk[9]=rk[3]^rk[8]
	str	r2,[r11,#-16]
	subs	r12,r12,#1
	str	r3,[r11,#-12]
#ifdef	__thumb2__
	itt	eq				@ Thumb2 thing, sanity check in ARM
#endif
	subeq	r2,r11,#216
	beq	.Ldone

	ldr	r7,[r11,#-32]
	ldr	r8,[r11,#-28]
	eor	r7,r7,r3			@ rk[10]=rk[4]^rk[9]
	eor	r9,r8,r7			@ rk[11]=rk[5]^rk[10]
	str	r7,[r11,#-8]
	str	r9,[r11,#-4]
	b	.L192_loop

.Lnot192:
#if __ARM_ARCH__<7
	ldrb	r8,[r12,#27]
	ldrb	r4,[r12,#26]
	ldrb	r5,[r12,#25]
	ldrb	r6,[r12,#24]
	orr	r8,r8,r4,lsl#8
	ldrb	r9,[r12,#31]
	orr	r8,r8,r5,lsl#16
	ldrb	r4,[r12,#30]
	orr	r8,r8,r6,lsl#24
	ldrb	r5,[r12,#29]
	ldrb	r6,[r12,#28]
	orr	r9,r9,r4,lsl#8
	orr	r9,r9,r5,lsl#16
	str	r8,[r11],#8
	orr	r9,r9,r6,lsl#24
	str	r9,[r11,#-4]
#else
	ldr	r8,[r12,#24]
	ldr	r9,[r12,#28]
#ifdef __ARMEL__
	rev	r8,r8
	rev	r9,r9
#endif
	str	r8,[r11],#8
	str	r9,[r11,#-4]
#endif

	mov	r12,#14
	str	r12,[r11,#240-32]
	add	r6,r10,#256			@ rcon
	mov	lr,#255
	mov	r12,#7

.L256_loop:
	and	r5,lr,r9,lsr#24
	and	r7,lr,r9,lsr#16
	ldrb	r5,[r10,r5]
	and	r8,lr,r9,lsr#8
	ldrb	r7,[r10,r7]
	and	r9,lr,r9
	ldrb	r8,[r10,r8]
	orr	r5,r5,r7,lsl#24
	ldrb	r9,[r10,r9]
	orr	r5,r5,r8,lsl#16
	ldr	r4,[r6],#4			@ rcon[i++]
	orr	r5,r5,r9,lsl#8
	eor	r9,r5,r4
	eor	r0,r0,r9			@ rk[8]=rk[0]^...
	eor	r1,r1,r0			@ rk[9]=rk[1]^rk[8]
	str	r0,[r11],#32
	eor	r2,r2,r1			@ rk[10]=rk[2]^rk[9]
	str	r1,[r11,#-28]
	eor	r3,r3,r2			@ rk[11]=rk[3]^rk[10]
	str	r2,[r11,#-24]
	subs	r12,r12,#1
	str	r3,[r11,#-20]
#ifdef	__thumb2__
	itt	eq				@ Thumb2 thing, sanity check in ARM
#endif
	subeq	r2,r11,#256
	beq	.Ldone

	and	r5,lr,r3
	and	r7,lr,r3,lsr#8
	ldrb	r5,[r10,r5]
	and	r8,lr,r3,lsr#16
	ldrb	r7,[r10,r7]
	and	r9,lr,r3,lsr#24
	ldrb	r8,[r10,r8]
	orr	r5,r5,r7,lsl#8
	ldrb	r9,[r10,r9]
	orr	r5,r5,r8,lsl#16
	ldr	r4,[r11,#-48]
	orr	r5,r5,r9,lsl#24

	ldr	r7,[r11,#-44]
	ldr	r8,[r11,#-40]
	eor	r4,r4,r5			@ rk[12]=rk[4]^...
	ldr	r9,[r11,#-36]
	eor	r7,r7,r4			@ rk[13]=rk[5]^rk[12]
	str	r4,[r11,#-16]
	eor	r8,r8,r7			@ rk[14]=rk[6]^rk[13]
	str	r7,[r11,#-12]
	eor	r9,r9,r8			@ rk[15]=rk[7]^rk[14]
	str	r8,[r11,#-8]
	str	r9,[r11,#-4]
	b	.L256_loop

.align	2
.Ldone:	mov	r0,#0
	ldmia   sp!,{r4-r12,lr}
.Labrt:
#if __ARM_ARCH__>=5
	bx	lr				@ .word	0xFF
#else
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	.word	0xFF			@ interoperable with Thumb ISA:-)
#endif
.size	AES_set_encrypt_key,.-AES_set_encrypt_key

.global AES_set_decrypt_key
.type   AES_set_decrypt_key,%function
.align	5
AES_set_decrypt_key:
	str	lr,[sp,#-4]!            @ push lr
	bl	_armv4_AES_set_encrypt_key
	teq	r0,#0
	ldr	lr,[sp],#4              @ pop lr
	bne	.Labrt

	mov	r0,r2			@ AES_set_encrypt_key preserves r2,
	mov	r1,r2			@ which is AES_KEY *key
	b	_armv4_AES_set_enc2dec_key
.size	AES_set_decrypt_key,.-AES_set_decrypt_key

@ void AES_set_enc2dec_key(const AES_KEY *inp,AES_KEY *out)
.global	AES_set_enc2dec_key
.type	AES_set_enc2dec_key,%function
.align	5
AES_set_enc2dec_key:
_armv4_AES_set_enc2dec_key:
	stmdb   sp!,{r4-r12,lr}

	ldr	r12,[r0,#240]
	mov	r7,r0			@ input
	add	r8,r0,r12,lsl#4
	mov	r11,r1			@ output
	add	r10,r1,r12,lsl#4
	str	r12,[r1,#240]

.Linv:	ldr	r0,[r7],#16
	ldr	r1,[r7,#-12]
	ldr	r2,[r7,#-8]
	ldr	r3,[r7,#-4]
	ldr	r4,[r8],#-16
	ldr	r5,[r8,#16+4]
	ldr	r6,[r8,#16+8]
	ldr	r9,[r8,#16+12]
	str	r0,[r10],#-16
	str	r1,[r10,#16+4]
	str	r2,[r10,#16+8]
	str	r3,[r10,#16+12]
	str	r4,[r11],#16
	str	r5,[r11,#-12]
	str	r6,[r11,#-8]
	str	r9,[r11,#-4]
	teq	r7,r8
	bne	.Linv

	ldr	r0,[r7]
	ldr	r1,[r7,#4]
	ldr	r2,[r7,#8]
	ldr	r3,[r7,#12]
	str	r0,[r11]
	str	r1,[r11,#4]
	str	r2,[r11,#8]
	str	r3,[r11,#12]
	sub	r11,r11,r12,lsl#3
	ldr	r0,[r11,#16]!		@ prefetch tp1
	mov	r7,#0xFF
	mov	r8,#0xFF
	orr	r7,r7,#0xFF
	orr	r8,r8,#0xFF
	orr	r7,r7,r7,lsl#16
	orr	r8,r8,r8,lsl#16
	sub	r12,r12,#1
	mvn	r9,r7
	mov	r12,r12,lsl#2	@ (rounds-1)*4

.Lmix:	and	r4,r0,r7
	and	r1,r0,r9
	sub	r4,r4,r4,lsr#7
	and	r4,r4,r8
	eor	r1,r4,r1,lsl#1	@ tp2

	and	r4,r1,r7
	and	r2,r1,r9
	sub	r4,r4,r4,lsr#7
	and	r4,r4,r8
	eor	r2,r4,r2,lsl#1	@ tp4

	and	r4,r2,r7
	and	r3,r2,r9
	sub	r4,r4,r4,lsr#7
	and	r4,r4,r8
	eor	r3,r4,r3,lsl#1	@ tp8

	eor	r4,r1,r2
	eor	r5,r0,r3		@ tp9
	eor	r4,r4,r3		@ tpe
	eor	r4,r4,r1,ror#24
	eor	r4,r4,r5,ror#24	@ ^= ROTATE(tpb=tp9^tp2,8)
	eor	r4,r4,r2,ror#16
	eor	r4,r4,r5,ror#16	@ ^= ROTATE(tpd=tp9^tp4,16)
	eor	r4,r4,r5,ror#8	@ ^= ROTATE(tp9,24)

	ldr	r0,[r11,#4]		@ prefetch tp1
	str	r4,[r11],#4
	subs	r12,r12,#1
	bne	.Lmix

	mov	r0,#0
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	.word	0xFF			@ interoperable with Thumb ISA:-)
#endif
.size	AES_set_enc2dec_key,.-AES_set_enc2dec_key

.type	AES_Td,%object
.align	5
AES_Td:
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
.word	0xFF, 0xFF, 0xFF, 0xFF
@ Td4[256]
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.size	AES_Td,.-AES_Td

@ void AES_decrypt(const unsigned char *in, unsigned char *out,
@ 		 const AES_KEY *key) {
.global AES_decrypt
.type   AES_decrypt,%function
.align	5
AES_decrypt:
#ifndef	__thumb2__
	sub	r3,pc,#8		@ AES_decrypt
#else
	adr	r3,.
#endif
	stmdb   sp!,{r1,r4-r12,lr}
#if defined(__thumb2__) || defined(__APPLE__)
	adr	r10,AES_Td
#else
	sub	r10,r3,#AES_decrypt-AES_Td	@ Td
#endif
	mov	r12,r0		@ inp
	mov	r11,r2
#if __ARM_ARCH__<7
	ldrb	r0,[r12,#3]	@ load input data in endian-neutral
	ldrb	r4,[r12,#2]	@ manner...
	ldrb	r5,[r12,#1]
	ldrb	r6,[r12,#0]
	orr	r0,r0,r4,lsl#8
	ldrb	r1,[r12,#7]
	orr	r0,r0,r5,lsl#16
	ldrb	r4,[r12,#6]
	orr	r0,r0,r6,lsl#24
	ldrb	r5,[r12,#5]
	ldrb	r6,[r12,#4]
	orr	r1,r1,r4,lsl#8
	ldrb	r2,[r12,#11]
	orr	r1,r1,r5,lsl#16
	ldrb	r4,[r12,#10]
	orr	r1,r1,r6,lsl#24
	ldrb	r5,[r12,#9]
	ldrb	r6,[r12,#8]
	orr	r2,r2,r4,lsl#8
	ldrb	r3,[r12,#15]
	orr	r2,r2,r5,lsl#16
	ldrb	r4,[r12,#14]
	orr	r2,r2,r6,lsl#24
	ldrb	r5,[r12,#13]
	ldrb	r6,[r12,#12]
	orr	r3,r3,r4,lsl#8
	orr	r3,r3,r5,lsl#16
	orr	r3,r3,r6,lsl#24
#else
	ldr	r0,[r12,#0]
	ldr	r1,[r12,#4]
	ldr	r2,[r12,#8]
	ldr	r3,[r12,#12]
#ifdef __ARMEL__
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
#endif
	bl	_armv4_AES_decrypt

	ldr	r12,[sp],#4		@ pop out
#if __ARM_ARCH__>=7
#ifdef __ARMEL__
	rev	r0,r0
	rev	r1,r1
	rev	r2,r2
	rev	r3,r3
#endif
	str	r0,[r12,#0]
	str	r1,[r12,#4]
	str	r2,[r12,#8]
	str	r3,[r12,#12]
#else
	mov	r4,r0,lsr#24		@ write output in endian-neutral
	mov	r5,r0,lsr#16		@ manner...
	mov	r6,r0,lsr#8
	strb	r4,[r12,#0]
	strb	r5,[r12,#1]
	mov	r4,r1,lsr#24
	strb	r6,[r12,#2]
	mov	r5,r1,lsr#16
	strb	r0,[r12,#3]
	mov	r6,r1,lsr#8
	strb	r4,[r12,#4]
	strb	r5,[r12,#5]
	mov	r4,r2,lsr#24
	strb	r6,[r12,#6]
	mov	r5,r2,lsr#16
	strb	r1,[r12,#7]
	mov	r6,r2,lsr#8
	strb	r4,[r12,#8]
	strb	r5,[r12,#9]
	mov	r4,r3,lsr#24
	strb	r6,[r12,#10]
	mov	r5,r3,lsr#16
	strb	r2,[r12,#11]
	mov	r6,r3,lsr#8
	strb	r4,[r12,#12]
	strb	r5,[r12,#13]
	strb	r6,[r12,#14]
	strb	r3,[r12,#15]
#endif
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	.word	0xFF			@ interoperable with Thumb ISA:-)
#endif
.size	AES_decrypt,.-AES_decrypt

.type   _armv4_AES_decrypt,%function
.align	2
_armv4_AES_decrypt:
	str	lr,[sp,#-4]!		@ push lr
	ldmia	r11!,{r4-r7}
	eor	r0,r0,r4
	ldr	r12,[r11,#240-16]
	eor	r1,r1,r5
	eor	r2,r2,r6
	eor	r3,r3,r7
	sub	r12,r12,#1
	mov	lr,#255

	and	r7,lr,r0,lsr#16
	and	r8,lr,r0,lsr#8
	and	r9,lr,r0
	mov	r0,r0,lsr#24
.Ldec_loop:
	ldr	r4,[r10,r7,lsl#2]	@ Td1[s0>>16]
	and	r7,lr,r1		@ i0
	ldr	r5,[r10,r8,lsl#2]	@ Td2[s0>>8]
	and	r8,lr,r1,lsr#16
	ldr	r6,[r10,r9,lsl#2]	@ Td3[s0>>0]
	and	r9,lr,r1,lsr#8
	ldr	r0,[r10,r0,lsl#2]	@ Td0[s0>>24]
	mov	r1,r1,lsr#24

	ldr	r7,[r10,r7,lsl#2]	@ Td3[s1>>0]
	ldr	r8,[r10,r8,lsl#2]	@ Td1[s1>>16]
	ldr	r9,[r10,r9,lsl#2]	@ Td2[s1>>8]
	eor	r0,r0,r7,ror#24
	ldr	r1,[r10,r1,lsl#2]	@ Td0[s1>>24]
	and	r7,lr,r2,lsr#8	@ i0
	eor	r5,r8,r5,ror#8
	and	r8,lr,r2		@ i1
	eor	r6,r9,r6,ror#8
	and	r9,lr,r2,lsr#16
	ldr	r7,[r10,r7,lsl#2]	@ Td2[s2>>8]
	eor	r1,r1,r4,ror#8
	ldr	r8,[r10,r8,lsl#2]	@ Td3[s2>>0]
	mov	r2,r2,lsr#24

	ldr	r9,[r10,r9,lsl#2]	@ Td1[s2>>16]
	eor	r0,r0,r7,ror#16
	ldr	r2,[r10,r2,lsl#2]	@ Td0[s2>>24]
	and	r7,lr,r3,lsr#16	@ i0
	eor	r1,r1,r8,ror#24
	and	r8,lr,r3,lsr#8	@ i1
	eor	r6,r9,r6,ror#8
	and	r9,lr,r3		@ i2
	ldr	r7,[r10,r7,lsl#2]	@ Td1[s3>>16]
	eor	r2,r2,r5,ror#8
	ldr	r8,[r10,r8,lsl#2]	@ Td2[s3>>8]
	mov	r3,r3,lsr#24

	ldr	r9,[r10,r9,lsl#2]	@ Td3[s3>>0]
	eor	r0,r0,r7,ror#8
	ldr	r7,[r11],#16
	eor	r1,r1,r8,ror#16
	ldr	r3,[r10,r3,lsl#2]	@ Td0[s3>>24]
	eor	r2,r2,r9,ror#24

	ldr	r4,[r11,#-12]
	eor	r0,r0,r7
	ldr	r5,[r11,#-8]
	eor	r3,r3,r6,ror#8
	ldr	r6,[r11,#-4]
	and	r7,lr,r0,lsr#16
	eor	r1,r1,r4
	and	r8,lr,r0,lsr#8
	eor	r2,r2,r5
	and	r9,lr,r0
	eor	r3,r3,r6
	mov	r0,r0,lsr#24

	subs	r12,r12,#1
	bne	.Ldec_loop

	add	r10,r10,#1024

	ldr	r5,[r10,#0]		@ prefetch Td4
	ldr	r6,[r10,#32]
	ldr	r4,[r10,#64]
	ldr	r5,[r10,#96]
	ldr	r6,[r10,#128]
	ldr	r4,[r10,#160]
	ldr	r5,[r10,#192]
	ldr	r6,[r10,#224]

	ldrb	r0,[r10,r0]		@ Td4[s0>>24]
	ldrb	r4,[r10,r7]		@ Td4[s0>>16]
	and	r7,lr,r1		@ i0
	ldrb	r5,[r10,r8]		@ Td4[s0>>8]
	and	r8,lr,r1,lsr#16
	ldrb	r6,[r10,r9]		@ Td4[s0>>0]
	and	r9,lr,r1,lsr#8

	add	r1,r10,r1,lsr#24
	ldrb	r7,[r10,r7]		@ Td4[s1>>0]
	ldrb	r1,[r1]		@ Td4[s1>>24]
	ldrb	r8,[r10,r8]		@ Td4[s1>>16]
	eor	r0,r7,r0,lsl#24
	ldrb	r9,[r10,r9]		@ Td4[s1>>8]
	eor	r1,r4,r1,lsl#8
	and	r7,lr,r2,lsr#8	@ i0
	eor	r5,r5,r8,lsl#8
	and	r8,lr,r2		@ i1
	ldrb	r7,[r10,r7]		@ Td4[s2>>8]
	eor	r6,r6,r9,lsl#8
	ldrb	r8,[r10,r8]		@ Td4[s2>>0]
	and	r9,lr,r2,lsr#16

	add	r2,r10,r2,lsr#24
	ldrb	r2,[r2]		@ Td4[s2>>24]
	eor	r0,r0,r7,lsl#8
	ldrb	r9,[r10,r9]		@ Td4[s2>>16]
	eor	r1,r8,r1,lsl#16
	and	r7,lr,r3,lsr#16	@ i0
	eor	r2,r5,r2,lsl#16
	and	r8,lr,r3,lsr#8	@ i1
	ldrb	r7,[r10,r7]		@ Td4[s3>>16]
	eor	r6,r6,r9,lsl#16
	ldrb	r8,[r10,r8]		@ Td4[s3>>8]
	and	r9,lr,r3		@ i2

	add	r3,r10,r3,lsr#24
	ldrb	r9,[r10,r9]		@ Td4[s3>>0]
	ldrb	r3,[r3]		@ Td4[s3>>24]
	eor	r0,r0,r7,lsl#16
	ldr	r7,[r11,#0]
	eor	r1,r1,r8,lsl#8
	ldr	r4,[r11,#4]
	eor	r2,r9,r2,lsl#8
	ldr	r5,[r11,#8]
	eor	r3,r6,r3,lsl#24
	ldr	r6,[r11,#12]

	eor	r0,r0,r7
	eor	r1,r1,r4
	eor	r2,r2,r5
	eor	r3,r3,r6

	sub	r10,r10,#1024
	ldr	pc,[sp],#4		@ pop and return
.size	_armv4_AES_decrypt,.-_armv4_AES_decrypt
.asciz	"AES for ARMv4, CRYPTOGAMS by <appro@openssl.org>"
.align	2
