#! /usr/bin/env perl
# Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# AES for ARMv4

# January 2007.
#
# Code uses single 1K S-box and is >2 times faster than code generated
# by gcc-3.4.1. This is thanks to unique feature of ARMv4 ISA, which
# allows to merge logical or arithmetic operation with shift or rotate
# in one instruction and emit combined result every cycle. The module
# is endian-neutral. The performance is ~42 cycles/byte for 128-bit
# key [on single-issue Xscale PXA250 core].

# May 2007.
#
# AES_set_[en|de]crypt_key is added.

# July 2010.
#
# Rescheduling for dual-issue pipeline resulted in 12% improvement on
# Cortex A8 core and ~25 cycles per byte processed with 128-bit key.

# February 2011.
#
# Profiler-assisted and platform-specific optimization resulted in 16%
# improvement on Cortex A8 core and ~21.5 cycles per byte.

$flavour = shift;
if ($flavour=~/\w[\w\-]*\.\w+$/) { $output=$flavour; undef $flavour; }
else { while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {} }

if ($flavour && $flavour ne "void") {
    $0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
    ( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
    ( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
    die "can't locate arm-xlate.pl";

    open STDOUT,"| \"$^X\" $xlate $flavour $output";
} else {
    open STDOUT,">$output";
}

$s0="r0";
$s1="r1";
$s2="r2";
$s3="r3";
$t1="r4";
$t2="r5";
$t3="r6";
$i1="r7";
$i2="r8";
$i3="r9";

$tbl="r10";
$key="r11";
$rounds="r12";

$code=<<___;
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
	adr	$tbl,AES_Te
#else
	sub	$tbl,r3,#AES_encrypt-AES_Te	@ Te
#endif
	mov	$rounds,r0		@ inp
	mov	$key,r2
#if __ARM_ARCH__<7
	ldrb	$s0,[$rounds,#3]	@ load input data in endian-neutral
	ldrb	$t1,[$rounds,#2]	@ manner...
	ldrb	$t2,[$rounds,#1]
	ldrb	$t3,[$rounds,#0]
	orr	$s0,$s0,$t1,lsl#8
	ldrb	$s1,[$rounds,#7]
	orr	$s0,$s0,$t2,lsl#16
	ldrb	$t1,[$rounds,#6]
	orr	$s0,$s0,$t3,lsl#24
	ldrb	$t2,[$rounds,#5]
	ldrb	$t3,[$rounds,#4]
	orr	$s1,$s1,$t1,lsl#8
	ldrb	$s2,[$rounds,#11]
	orr	$s1,$s1,$t2,lsl#16
	ldrb	$t1,[$rounds,#10]
	orr	$s1,$s1,$t3,lsl#24
	ldrb	$t2,[$rounds,#9]
	ldrb	$t3,[$rounds,#8]
	orr	$s2,$s2,$t1,lsl#8
	ldrb	$s3,[$rounds,#15]
	orr	$s2,$s2,$t2,lsl#16
	ldrb	$t1,[$rounds,#14]
	orr	$s2,$s2,$t3,lsl#24
	ldrb	$t2,[$rounds,#13]
	ldrb	$t3,[$rounds,#12]
	orr	$s3,$s3,$t1,lsl#8
	orr	$s3,$s3,$t2,lsl#16
	orr	$s3,$s3,$t3,lsl#24
#else
	ldr	$s0,[$rounds,#0]
	ldr	$s1,[$rounds,#4]
	ldr	$s2,[$rounds,#8]
	ldr	$s3,[$rounds,#12]
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
#endif
	bl	_armv4_AES_encrypt

	ldr	$rounds,[sp],#4		@ pop out
#if __ARM_ARCH__>=7
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
	str	$s0,[$rounds,#0]
	str	$s1,[$rounds,#4]
	str	$s2,[$rounds,#8]
	str	$s3,[$rounds,#12]
#else
	mov	$t1,$s0,lsr#24		@ write output in endian-neutral
	mov	$t2,$s0,lsr#16		@ manner...
	mov	$t3,$s0,lsr#8
	strb	$t1,[$rounds,#0]
	strb	$t2,[$rounds,#1]
	mov	$t1,$s1,lsr#24
	strb	$t3,[$rounds,#2]
	mov	$t2,$s1,lsr#16
	strb	$s0,[$rounds,#3]
	mov	$t3,$s1,lsr#8
	strb	$t1,[$rounds,#4]
	strb	$t2,[$rounds,#5]
	mov	$t1,$s2,lsr#24
	strb	$t3,[$rounds,#6]
	mov	$t2,$s2,lsr#16
	strb	$s1,[$rounds,#7]
	mov	$t3,$s2,lsr#8
	strb	$t1,[$rounds,#8]
	strb	$t2,[$rounds,#9]
	mov	$t1,$s3,lsr#24
	strb	$t3,[$rounds,#10]
	mov	$t2,$s3,lsr#16
	strb	$s2,[$rounds,#11]
	mov	$t3,$s3,lsr#8
	strb	$t1,[$rounds,#12]
	strb	$t2,[$rounds,#13]
	strb	$t3,[$rounds,#14]
	strb	$s3,[$rounds,#15]
#endif
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
#endif
.size	AES_encrypt,.-AES_encrypt

.type   _armv4_AES_encrypt,%function
.align	2
_armv4_AES_encrypt:
	str	lr,[sp,#-4]!		@ push lr
	ldmia	$key!,{$t1-$i1}
	eor	$s0,$s0,$t1
	ldr	$rounds,[$key,#240-16]
	eor	$s1,$s1,$t2
	eor	$s2,$s2,$t3
	eor	$s3,$s3,$i1
	sub	$rounds,$rounds,#1
	mov	lr,#255

	and	$i1,lr,$s0
	and	$i2,lr,$s0,lsr#8
	and	$i3,lr,$s0,lsr#16
	mov	$s0,$s0,lsr#24
.Lenc_loop:
	ldr	$t1,[$tbl,$i1,lsl#2]	@ Te3[s0>>0]
	and	$i1,lr,$s1,lsr#16	@ i0
	ldr	$t2,[$tbl,$i2,lsl#2]	@ Te2[s0>>8]
	and	$i2,lr,$s1
	ldr	$t3,[$tbl,$i3,lsl#2]	@ Te1[s0>>16]
	and	$i3,lr,$s1,lsr#8
	ldr	$s0,[$tbl,$s0,lsl#2]	@ Te0[s0>>24]
	mov	$s1,$s1,lsr#24

	ldr	$i1,[$tbl,$i1,lsl#2]	@ Te1[s1>>16]
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Te3[s1>>0]
	ldr	$i3,[$tbl,$i3,lsl#2]	@ Te2[s1>>8]
	eor	$s0,$s0,$i1,ror#8
	ldr	$s1,[$tbl,$s1,lsl#2]	@ Te0[s1>>24]
	and	$i1,lr,$s2,lsr#8	@ i0
	eor	$t2,$t2,$i2,ror#8
	and	$i2,lr,$s2,lsr#16	@ i1
	eor	$t3,$t3,$i3,ror#8
	and	$i3,lr,$s2
	ldr	$i1,[$tbl,$i1,lsl#2]	@ Te2[s2>>8]
	eor	$s1,$s1,$t1,ror#24
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Te1[s2>>16]
	mov	$s2,$s2,lsr#24

	ldr	$i3,[$tbl,$i3,lsl#2]	@ Te3[s2>>0]
	eor	$s0,$s0,$i1,ror#16
	ldr	$s2,[$tbl,$s2,lsl#2]	@ Te0[s2>>24]
	and	$i1,lr,$s3		@ i0
	eor	$s1,$s1,$i2,ror#8
	and	$i2,lr,$s3,lsr#8	@ i1
	eor	$t3,$t3,$i3,ror#16
	and	$i3,lr,$s3,lsr#16	@ i2
	ldr	$i1,[$tbl,$i1,lsl#2]	@ Te3[s3>>0]
	eor	$s2,$s2,$t2,ror#16
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Te2[s3>>8]
	mov	$s3,$s3,lsr#24

	ldr	$i3,[$tbl,$i3,lsl#2]	@ Te1[s3>>16]
	eor	$s0,$s0,$i1,ror#24
	ldr	$i1,[$key],#16
	eor	$s1,$s1,$i2,ror#16
	ldr	$s3,[$tbl,$s3,lsl#2]	@ Te0[s3>>24]
	eor	$s2,$s2,$i3,ror#8
	ldr	$t1,[$key,#-12]
	eor	$s3,$s3,$t3,ror#8

	ldr	$t2,[$key,#-8]
	eor	$s0,$s0,$i1
	ldr	$t3,[$key,#-4]
	and	$i1,lr,$s0
	eor	$s1,$s1,$t1
	and	$i2,lr,$s0,lsr#8
	eor	$s2,$s2,$t2
	and	$i3,lr,$s0,lsr#16
	eor	$s3,$s3,$t3
	mov	$s0,$s0,lsr#24

	subs	$rounds,$rounds,#1
	bne	.Lenc_loop

	add	$tbl,$tbl,#2

	ldrb	$t1,[$tbl,$i1,lsl#2]	@ Te4[s0>>0]
	and	$i1,lr,$s1,lsr#16	@ i0
	ldrb	$t2,[$tbl,$i2,lsl#2]	@ Te4[s0>>8]
	and	$i2,lr,$s1
	ldrb	$t3,[$tbl,$i3,lsl#2]	@ Te4[s0>>16]
	and	$i3,lr,$s1,lsr#8
	ldrb	$s0,[$tbl,$s0,lsl#2]	@ Te4[s0>>24]
	mov	$s1,$s1,lsr#24

	ldrb	$i1,[$tbl,$i1,lsl#2]	@ Te4[s1>>16]
	ldrb	$i2,[$tbl,$i2,lsl#2]	@ Te4[s1>>0]
	ldrb	$i3,[$tbl,$i3,lsl#2]	@ Te4[s1>>8]
	eor	$s0,$i1,$s0,lsl#8
	ldrb	$s1,[$tbl,$s1,lsl#2]	@ Te4[s1>>24]
	and	$i1,lr,$s2,lsr#8	@ i0
	eor	$t2,$i2,$t2,lsl#8
	and	$i2,lr,$s2,lsr#16	@ i1
	eor	$t3,$i3,$t3,lsl#8
	and	$i3,lr,$s2
	ldrb	$i1,[$tbl,$i1,lsl#2]	@ Te4[s2>>8]
	eor	$s1,$t1,$s1,lsl#24
	ldrb	$i2,[$tbl,$i2,lsl#2]	@ Te4[s2>>16]
	mov	$s2,$s2,lsr#24

	ldrb	$i3,[$tbl,$i3,lsl#2]	@ Te4[s2>>0]
	eor	$s0,$i1,$s0,lsl#8
	ldrb	$s2,[$tbl,$s2,lsl#2]	@ Te4[s2>>24]
	and	$i1,lr,$s3		@ i0
	eor	$s1,$s1,$i2,lsl#16
	and	$i2,lr,$s3,lsr#8	@ i1
	eor	$t3,$i3,$t3,lsl#8
	and	$i3,lr,$s3,lsr#16	@ i2
	ldrb	$i1,[$tbl,$i1,lsl#2]	@ Te4[s3>>0]
	eor	$s2,$t2,$s2,lsl#24
	ldrb	$i2,[$tbl,$i2,lsl#2]	@ Te4[s3>>8]
	mov	$s3,$s3,lsr#24

	ldrb	$i3,[$tbl,$i3,lsl#2]	@ Te4[s3>>16]
	eor	$s0,$i1,$s0,lsl#8
	ldr	$i1,[$key,#0]
	ldrb	$s3,[$tbl,$s3,lsl#2]	@ Te4[s3>>24]
	eor	$s1,$s1,$i2,lsl#8
	ldr	$t1,[$key,#4]
	eor	$s2,$s2,$i3,lsl#16
	ldr	$t2,[$key,#8]
	eor	$s3,$t3,$s3,lsl#24
	ldr	$t3,[$key,#12]

	eor	$s0,$s0,$i1
	eor	$s1,$s1,$t1
	eor	$s2,$s2,$t2
	eor	$s3,$s3,$t3

	sub	$tbl,$tbl,#2
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
	mov	$rounds,r0		@ inp
	mov	lr,r1			@ bits
	mov	$key,r2			@ key

#if defined(__thumb2__) || defined(__APPLE__)
	adr	$tbl,AES_Te+1024				@ Te4
#else
	sub	$tbl,r3,#_armv4_AES_set_encrypt_key-AES_Te-1024	@ Te4
#endif

#if __ARM_ARCH__<7
	ldrb	$s0,[$rounds,#3]	@ load input data in endian-neutral
	ldrb	$t1,[$rounds,#2]	@ manner...
	ldrb	$t2,[$rounds,#1]
	ldrb	$t3,[$rounds,#0]
	orr	$s0,$s0,$t1,lsl#8
	ldrb	$s1,[$rounds,#7]
	orr	$s0,$s0,$t2,lsl#16
	ldrb	$t1,[$rounds,#6]
	orr	$s0,$s0,$t3,lsl#24
	ldrb	$t2,[$rounds,#5]
	ldrb	$t3,[$rounds,#4]
	orr	$s1,$s1,$t1,lsl#8
	ldrb	$s2,[$rounds,#11]
	orr	$s1,$s1,$t2,lsl#16
	ldrb	$t1,[$rounds,#10]
	orr	$s1,$s1,$t3,lsl#24
	ldrb	$t2,[$rounds,#9]
	ldrb	$t3,[$rounds,#8]
	orr	$s2,$s2,$t1,lsl#8
	ldrb	$s3,[$rounds,#15]
	orr	$s2,$s2,$t2,lsl#16
	ldrb	$t1,[$rounds,#14]
	orr	$s2,$s2,$t3,lsl#24
	ldrb	$t2,[$rounds,#13]
	ldrb	$t3,[$rounds,#12]
	orr	$s3,$s3,$t1,lsl#8
	str	$s0,[$key],#16
	orr	$s3,$s3,$t2,lsl#16
	str	$s1,[$key,#-12]
	orr	$s3,$s3,$t3,lsl#24
	str	$s2,[$key,#-8]
	str	$s3,[$key,#-4]
#else
	ldr	$s0,[$rounds,#0]
	ldr	$s1,[$rounds,#4]
	ldr	$s2,[$rounds,#8]
	ldr	$s3,[$rounds,#12]
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
	str	$s0,[$key],#16
	str	$s1,[$key,#-12]
	str	$s2,[$key,#-8]
	str	$s3,[$key,#-4]
#endif

	teq	lr,#128
	bne	.Lnot128
	mov	$rounds,#10
	str	$rounds,[$key,#240-16]
	add	$t3,$tbl,#256			@ rcon
	mov	lr,#255

.L128_loop:
	and	$t2,lr,$s3,lsr#24
	and	$i1,lr,$s3,lsr#16
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$s3,lsr#8
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$s3
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#24
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$t3],#4			@ rcon[i++]
	orr	$t2,$t2,$i3,lsl#8
	eor	$t2,$t2,$t1
	eor	$s0,$s0,$t2			@ rk[4]=rk[0]^...
	eor	$s1,$s1,$s0			@ rk[5]=rk[1]^rk[4]
	str	$s0,[$key],#16
	eor	$s2,$s2,$s1			@ rk[6]=rk[2]^rk[5]
	str	$s1,[$key,#-12]
	eor	$s3,$s3,$s2			@ rk[7]=rk[3]^rk[6]
	str	$s2,[$key,#-8]
	subs	$rounds,$rounds,#1
	str	$s3,[$key,#-4]
	bne	.L128_loop
	sub	r2,$key,#176
	b	.Ldone

.Lnot128:
#if __ARM_ARCH__<7
	ldrb	$i2,[$rounds,#19]
	ldrb	$t1,[$rounds,#18]
	ldrb	$t2,[$rounds,#17]
	ldrb	$t3,[$rounds,#16]
	orr	$i2,$i2,$t1,lsl#8
	ldrb	$i3,[$rounds,#23]
	orr	$i2,$i2,$t2,lsl#16
	ldrb	$t1,[$rounds,#22]
	orr	$i2,$i2,$t3,lsl#24
	ldrb	$t2,[$rounds,#21]
	ldrb	$t3,[$rounds,#20]
	orr	$i3,$i3,$t1,lsl#8
	orr	$i3,$i3,$t2,lsl#16
	str	$i2,[$key],#8
	orr	$i3,$i3,$t3,lsl#24
	str	$i3,[$key,#-4]
#else
	ldr	$i2,[$rounds,#16]
	ldr	$i3,[$rounds,#20]
#ifdef __ARMEL__
	rev	$i2,$i2
	rev	$i3,$i3
#endif
	str	$i2,[$key],#8
	str	$i3,[$key,#-4]
#endif

	teq	lr,#192
	bne	.Lnot192
	mov	$rounds,#12
	str	$rounds,[$key,#240-24]
	add	$t3,$tbl,#256			@ rcon
	mov	lr,#255
	mov	$rounds,#8

.L192_loop:
	and	$t2,lr,$i3,lsr#24
	and	$i1,lr,$i3,lsr#16
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$i3,lsr#8
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$i3
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#24
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$t3],#4			@ rcon[i++]
	orr	$t2,$t2,$i3,lsl#8
	eor	$i3,$t2,$t1
	eor	$s0,$s0,$i3			@ rk[6]=rk[0]^...
	eor	$s1,$s1,$s0			@ rk[7]=rk[1]^rk[6]
	str	$s0,[$key],#24
	eor	$s2,$s2,$s1			@ rk[8]=rk[2]^rk[7]
	str	$s1,[$key,#-20]
	eor	$s3,$s3,$s2			@ rk[9]=rk[3]^rk[8]
	str	$s2,[$key,#-16]
	subs	$rounds,$rounds,#1
	str	$s3,[$key,#-12]
#ifdef	__thumb2__
	itt	eq				@ Thumb2 thing, sanity check in ARM
#endif
	subeq	r2,$key,#216
	beq	.Ldone

	ldr	$i1,[$key,#-32]
	ldr	$i2,[$key,#-28]
	eor	$i1,$i1,$s3			@ rk[10]=rk[4]^rk[9]
	eor	$i3,$i2,$i1			@ rk[11]=rk[5]^rk[10]
	str	$i1,[$key,#-8]
	str	$i3,[$key,#-4]
	b	.L192_loop

.Lnot192:
#if __ARM_ARCH__<7
	ldrb	$i2,[$rounds,#27]
	ldrb	$t1,[$rounds,#26]
	ldrb	$t2,[$rounds,#25]
	ldrb	$t3,[$rounds,#24]
	orr	$i2,$i2,$t1,lsl#8
	ldrb	$i3,[$rounds,#31]
	orr	$i2,$i2,$t2,lsl#16
	ldrb	$t1,[$rounds,#30]
	orr	$i2,$i2,$t3,lsl#24
	ldrb	$t2,[$rounds,#29]
	ldrb	$t3,[$rounds,#28]
	orr	$i3,$i3,$t1,lsl#8
	orr	$i3,$i3,$t2,lsl#16
	str	$i2,[$key],#8
	orr	$i3,$i3,$t3,lsl#24
	str	$i3,[$key,#-4]
#else
	ldr	$i2,[$rounds,#24]
	ldr	$i3,[$rounds,#28]
#ifdef __ARMEL__
	rev	$i2,$i2
	rev	$i3,$i3
#endif
	str	$i2,[$key],#8
	str	$i3,[$key,#-4]
#endif

	mov	$rounds,#14
	str	$rounds,[$key,#240-32]
	add	$t3,$tbl,#256			@ rcon
	mov	lr,#255
	mov	$rounds,#7

.L256_loop:
	and	$t2,lr,$i3,lsr#24
	and	$i1,lr,$i3,lsr#16
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$i3,lsr#8
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$i3
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#24
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$t3],#4			@ rcon[i++]
	orr	$t2,$t2,$i3,lsl#8
	eor	$i3,$t2,$t1
	eor	$s0,$s0,$i3			@ rk[8]=rk[0]^...
	eor	$s1,$s1,$s0			@ rk[9]=rk[1]^rk[8]
	str	$s0,[$key],#32
	eor	$s2,$s2,$s1			@ rk[10]=rk[2]^rk[9]
	str	$s1,[$key,#-28]
	eor	$s3,$s3,$s2			@ rk[11]=rk[3]^rk[10]
	str	$s2,[$key,#-24]
	subs	$rounds,$rounds,#1
	str	$s3,[$key,#-20]
#ifdef	__thumb2__
	itt	eq				@ Thumb2 thing, sanity check in ARM
#endif
	subeq	r2,$key,#256
	beq	.Ldone

	and	$t2,lr,$s3
	and	$i1,lr,$s3,lsr#8
	ldrb	$t2,[$tbl,$t2]
	and	$i2,lr,$s3,lsr#16
	ldrb	$i1,[$tbl,$i1]
	and	$i3,lr,$s3,lsr#24
	ldrb	$i2,[$tbl,$i2]
	orr	$t2,$t2,$i1,lsl#8
	ldrb	$i3,[$tbl,$i3]
	orr	$t2,$t2,$i2,lsl#16
	ldr	$t1,[$key,#-48]
	orr	$t2,$t2,$i3,lsl#24

	ldr	$i1,[$key,#-44]
	ldr	$i2,[$key,#-40]
	eor	$t1,$t1,$t2			@ rk[12]=rk[4]^...
	ldr	$i3,[$key,#-36]
	eor	$i1,$i1,$t1			@ rk[13]=rk[5]^rk[12]
	str	$t1,[$key,#-16]
	eor	$i2,$i2,$i1			@ rk[14]=rk[6]^rk[13]
	str	$i1,[$key,#-12]
	eor	$i3,$i3,$i2			@ rk[15]=rk[7]^rk[14]
	str	$i2,[$key,#-8]
	str	$i3,[$key,#-4]
	b	.L256_loop

.align	2
.Ldone:	mov	r0,#0
	ldmia   sp!,{r4-r12,lr}
.Labrt:
#if __ARM_ARCH__>=5
	ret				@ bx lr
#else
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
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

	ldr	$rounds,[r0,#240]
	mov	$i1,r0			@ input
	add	$i2,r0,$rounds,lsl#4
	mov	$key,r1			@ output
	add	$tbl,r1,$rounds,lsl#4
	str	$rounds,[r1,#240]

.Linv:	ldr	$s0,[$i1],#16
	ldr	$s1,[$i1,#-12]
	ldr	$s2,[$i1,#-8]
	ldr	$s3,[$i1,#-4]
	ldr	$t1,[$i2],#-16
	ldr	$t2,[$i2,#16+4]
	ldr	$t3,[$i2,#16+8]
	ldr	$i3,[$i2,#16+12]
	str	$s0,[$tbl],#-16
	str	$s1,[$tbl,#16+4]
	str	$s2,[$tbl,#16+8]
	str	$s3,[$tbl,#16+12]
	str	$t1,[$key],#16
	str	$t2,[$key,#-12]
	str	$t3,[$key,#-8]
	str	$i3,[$key,#-4]
	teq	$i1,$i2
	bne	.Linv

	ldr	$s0,[$i1]
	ldr	$s1,[$i1,#4]
	ldr	$s2,[$i1,#8]
	ldr	$s3,[$i1,#12]
	str	$s0,[$key]
	str	$s1,[$key,#4]
	str	$s2,[$key,#8]
	str	$s3,[$key,#12]
	sub	$key,$key,$rounds,lsl#3
___
$mask80=$i1;
$mask1b=$i2;
$mask7f=$i3;
$code.=<<___;
	ldr	$s0,[$key,#16]!		@ prefetch tp1
	mov	$mask80,#0xFF
	mov	$mask1b,#0xFF
	orr	$mask80,$mask80,#0xFF
	orr	$mask1b,$mask1b,#0xFF
	orr	$mask80,$mask80,$mask80,lsl#16
	orr	$mask1b,$mask1b,$mask1b,lsl#16
	sub	$rounds,$rounds,#1
	mvn	$mask7f,$mask80
	mov	$rounds,$rounds,lsl#2	@ (rounds-1)*4

.Lmix:	and	$t1,$s0,$mask80
	and	$s1,$s0,$mask7f
	sub	$t1,$t1,$t1,lsr#7
	and	$t1,$t1,$mask1b
	eor	$s1,$t1,$s1,lsl#1	@ tp2

	and	$t1,$s1,$mask80
	and	$s2,$s1,$mask7f
	sub	$t1,$t1,$t1,lsr#7
	and	$t1,$t1,$mask1b
	eor	$s2,$t1,$s2,lsl#1	@ tp4

	and	$t1,$s2,$mask80
	and	$s3,$s2,$mask7f
	sub	$t1,$t1,$t1,lsr#7
	and	$t1,$t1,$mask1b
	eor	$s3,$t1,$s3,lsl#1	@ tp8

	eor	$t1,$s1,$s2
	eor	$t2,$s0,$s3		@ tp9
	eor	$t1,$t1,$s3		@ tpe
	eor	$t1,$t1,$s1,ror#24
	eor	$t1,$t1,$t2,ror#24	@ ^= ROTATE(tpb=tp9^tp2,8)
	eor	$t1,$t1,$s2,ror#16
	eor	$t1,$t1,$t2,ror#16	@ ^= ROTATE(tpd=tp9^tp4,16)
	eor	$t1,$t1,$t2,ror#8	@ ^= ROTATE(tp9,24)

	ldr	$s0,[$key,#4]		@ prefetch tp1
	str	$t1,[$key],#4
	subs	$rounds,$rounds,#1
	bne	.Lmix

	mov	r0,#0
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
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
	adr	$tbl,AES_Td
#else
	sub	$tbl,r3,#AES_decrypt-AES_Td	@ Td
#endif
	mov	$rounds,r0		@ inp
	mov	$key,r2
#if __ARM_ARCH__<7
	ldrb	$s0,[$rounds,#3]	@ load input data in endian-neutral
	ldrb	$t1,[$rounds,#2]	@ manner...
	ldrb	$t2,[$rounds,#1]
	ldrb	$t3,[$rounds,#0]
	orr	$s0,$s0,$t1,lsl#8
	ldrb	$s1,[$rounds,#7]
	orr	$s0,$s0,$t2,lsl#16
	ldrb	$t1,[$rounds,#6]
	orr	$s0,$s0,$t3,lsl#24
	ldrb	$t2,[$rounds,#5]
	ldrb	$t3,[$rounds,#4]
	orr	$s1,$s1,$t1,lsl#8
	ldrb	$s2,[$rounds,#11]
	orr	$s1,$s1,$t2,lsl#16
	ldrb	$t1,[$rounds,#10]
	orr	$s1,$s1,$t3,lsl#24
	ldrb	$t2,[$rounds,#9]
	ldrb	$t3,[$rounds,#8]
	orr	$s2,$s2,$t1,lsl#8
	ldrb	$s3,[$rounds,#15]
	orr	$s2,$s2,$t2,lsl#16
	ldrb	$t1,[$rounds,#14]
	orr	$s2,$s2,$t3,lsl#24
	ldrb	$t2,[$rounds,#13]
	ldrb	$t3,[$rounds,#12]
	orr	$s3,$s3,$t1,lsl#8
	orr	$s3,$s3,$t2,lsl#16
	orr	$s3,$s3,$t3,lsl#24
#else
	ldr	$s0,[$rounds,#0]
	ldr	$s1,[$rounds,#4]
	ldr	$s2,[$rounds,#8]
	ldr	$s3,[$rounds,#12]
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
#endif
	bl	_armv4_AES_decrypt

	ldr	$rounds,[sp],#4		@ pop out
#if __ARM_ARCH__>=7
#ifdef __ARMEL__
	rev	$s0,$s0
	rev	$s1,$s1
	rev	$s2,$s2
	rev	$s3,$s3
#endif
	str	$s0,[$rounds,#0]
	str	$s1,[$rounds,#4]
	str	$s2,[$rounds,#8]
	str	$s3,[$rounds,#12]
#else
	mov	$t1,$s0,lsr#24		@ write output in endian-neutral
	mov	$t2,$s0,lsr#16		@ manner...
	mov	$t3,$s0,lsr#8
	strb	$t1,[$rounds,#0]
	strb	$t2,[$rounds,#1]
	mov	$t1,$s1,lsr#24
	strb	$t3,[$rounds,#2]
	mov	$t2,$s1,lsr#16
	strb	$s0,[$rounds,#3]
	mov	$t3,$s1,lsr#8
	strb	$t1,[$rounds,#4]
	strb	$t2,[$rounds,#5]
	mov	$t1,$s2,lsr#24
	strb	$t3,[$rounds,#6]
	mov	$t2,$s2,lsr#16
	strb	$s1,[$rounds,#7]
	mov	$t3,$s2,lsr#8
	strb	$t1,[$rounds,#8]
	strb	$t2,[$rounds,#9]
	mov	$t1,$s3,lsr#24
	strb	$t3,[$rounds,#10]
	mov	$t2,$s3,lsr#16
	strb	$s2,[$rounds,#11]
	mov	$t3,$s3,lsr#8
	strb	$t1,[$rounds,#12]
	strb	$t2,[$rounds,#13]
	strb	$t3,[$rounds,#14]
	strb	$s3,[$rounds,#15]
#endif
#if __ARM_ARCH__>=5
	ldmia	sp!,{r4-r12,pc}
#else
	ldmia   sp!,{r4-r12,lr}
	tst	lr,#1
	moveq	pc,lr			@ be binary compatible with V4, yet
	bx	lr			@ interoperable with Thumb ISA:-)
#endif
.size	AES_decrypt,.-AES_decrypt

.type   _armv4_AES_decrypt,%function
.align	2
_armv4_AES_decrypt:
	str	lr,[sp,#-4]!		@ push lr
	ldmia	$key!,{$t1-$i1}
	eor	$s0,$s0,$t1
	ldr	$rounds,[$key,#240-16]
	eor	$s1,$s1,$t2
	eor	$s2,$s2,$t3
	eor	$s3,$s3,$i1
	sub	$rounds,$rounds,#1
	mov	lr,#255

	and	$i1,lr,$s0,lsr#16
	and	$i2,lr,$s0,lsr#8
	and	$i3,lr,$s0
	mov	$s0,$s0,lsr#24
.Ldec_loop:
	ldr	$t1,[$tbl,$i1,lsl#2]	@ Td1[s0>>16]
	and	$i1,lr,$s1		@ i0
	ldr	$t2,[$tbl,$i2,lsl#2]	@ Td2[s0>>8]
	and	$i2,lr,$s1,lsr#16
	ldr	$t3,[$tbl,$i3,lsl#2]	@ Td3[s0>>0]
	and	$i3,lr,$s1,lsr#8
	ldr	$s0,[$tbl,$s0,lsl#2]	@ Td0[s0>>24]
	mov	$s1,$s1,lsr#24

	ldr	$i1,[$tbl,$i1,lsl#2]	@ Td3[s1>>0]
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Td1[s1>>16]
	ldr	$i3,[$tbl,$i3,lsl#2]	@ Td2[s1>>8]
	eor	$s0,$s0,$i1,ror#24
	ldr	$s1,[$tbl,$s1,lsl#2]	@ Td0[s1>>24]
	and	$i1,lr,$s2,lsr#8	@ i0
	eor	$t2,$i2,$t2,ror#8
	and	$i2,lr,$s2		@ i1
	eor	$t3,$i3,$t3,ror#8
	and	$i3,lr,$s2,lsr#16
	ldr	$i1,[$tbl,$i1,lsl#2]	@ Td2[s2>>8]
	eor	$s1,$s1,$t1,ror#8
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Td3[s2>>0]
	mov	$s2,$s2,lsr#24

	ldr	$i3,[$tbl,$i3,lsl#2]	@ Td1[s2>>16]
	eor	$s0,$s0,$i1,ror#16
	ldr	$s2,[$tbl,$s2,lsl#2]	@ Td0[s2>>24]
	and	$i1,lr,$s3,lsr#16	@ i0
	eor	$s1,$s1,$i2,ror#24
	and	$i2,lr,$s3,lsr#8	@ i1
	eor	$t3,$i3,$t3,ror#8
	and	$i3,lr,$s3		@ i2
	ldr	$i1,[$tbl,$i1,lsl#2]	@ Td1[s3>>16]
	eor	$s2,$s2,$t2,ror#8
	ldr	$i2,[$tbl,$i2,lsl#2]	@ Td2[s3>>8]
	mov	$s3,$s3,lsr#24

	ldr	$i3,[$tbl,$i3,lsl#2]	@ Td3[s3>>0]
	eor	$s0,$s0,$i1,ror#8
	ldr	$i1,[$key],#16
	eor	$s1,$s1,$i2,ror#16
	ldr	$s3,[$tbl,$s3,lsl#2]	@ Td0[s3>>24]
	eor	$s2,$s2,$i3,ror#24

	ldr	$t1,[$key,#-12]
	eor	$s0,$s0,$i1
	ldr	$t2,[$key,#-8]
	eor	$s3,$s3,$t3,ror#8
	ldr	$t3,[$key,#-4]
	and	$i1,lr,$s0,lsr#16
	eor	$s1,$s1,$t1
	and	$i2,lr,$s0,lsr#8
	eor	$s2,$s2,$t2
	and	$i3,lr,$s0
	eor	$s3,$s3,$t3
	mov	$s0,$s0,lsr#24

	subs	$rounds,$rounds,#1
	bne	.Ldec_loop

	add	$tbl,$tbl,#1024

	ldr	$t2,[$tbl,#0]		@ prefetch Td4
	ldr	$t3,[$tbl,#32]
	ldr	$t1,[$tbl,#64]
	ldr	$t2,[$tbl,#96]
	ldr	$t3,[$tbl,#128]
	ldr	$t1,[$tbl,#160]
	ldr	$t2,[$tbl,#192]
	ldr	$t3,[$tbl,#224]

	ldrb	$s0,[$tbl,$s0]		@ Td4[s0>>24]
	ldrb	$t1,[$tbl,$i1]		@ Td4[s0>>16]
	and	$i1,lr,$s1		@ i0
	ldrb	$t2,[$tbl,$i2]		@ Td4[s0>>8]
	and	$i2,lr,$s1,lsr#16
	ldrb	$t3,[$tbl,$i3]		@ Td4[s0>>0]
	and	$i3,lr,$s1,lsr#8

	add	$s1,$tbl,$s1,lsr#24
	ldrb	$i1,[$tbl,$i1]		@ Td4[s1>>0]
	ldrb	$s1,[$s1]		@ Td4[s1>>24]
	ldrb	$i2,[$tbl,$i2]		@ Td4[s1>>16]
	eor	$s0,$i1,$s0,lsl#24
	ldrb	$i3,[$tbl,$i3]		@ Td4[s1>>8]
	eor	$s1,$t1,$s1,lsl#8
	and	$i1,lr,$s2,lsr#8	@ i0
	eor	$t2,$t2,$i2,lsl#8
	and	$i2,lr,$s2		@ i1
	ldrb	$i1,[$tbl,$i1]		@ Td4[s2>>8]
	eor	$t3,$t3,$i3,lsl#8
	ldrb	$i2,[$tbl,$i2]		@ Td4[s2>>0]
	and	$i3,lr,$s2,lsr#16

	add	$s2,$tbl,$s2,lsr#24
	ldrb	$s2,[$s2]		@ Td4[s2>>24]
	eor	$s0,$s0,$i1,lsl#8
	ldrb	$i3,[$tbl,$i3]		@ Td4[s2>>16]
	eor	$s1,$i2,$s1,lsl#16
	and	$i1,lr,$s3,lsr#16	@ i0
	eor	$s2,$t2,$s2,lsl#16
	and	$i2,lr,$s3,lsr#8	@ i1
	ldrb	$i1,[$tbl,$i1]		@ Td4[s3>>16]
	eor	$t3,$t3,$i3,lsl#16
	ldrb	$i2,[$tbl,$i2]		@ Td4[s3>>8]
	and	$i3,lr,$s3		@ i2

	add	$s3,$tbl,$s3,lsr#24
	ldrb	$i3,[$tbl,$i3]		@ Td4[s3>>0]
	ldrb	$s3,[$s3]		@ Td4[s3>>24]
	eor	$s0,$s0,$i1,lsl#16
	ldr	$i1,[$key,#0]
	eor	$s1,$s1,$i2,lsl#8
	ldr	$t1,[$key,#4]
	eor	$s2,$i3,$s2,lsl#8
	ldr	$t2,[$key,#8]
	eor	$s3,$t3,$s3,lsl#24
	ldr	$t3,[$key,#12]

	eor	$s0,$s0,$i1
	eor	$s1,$s1,$t1
	eor	$s2,$s2,$t2
	eor	$s3,$s3,$t3

	sub	$tbl,$tbl,#1024
	ldr	pc,[sp],#4		@ pop and return
.size	_armv4_AES_decrypt,.-_armv4_AES_decrypt
.asciz	"AES for ARMv4, CRYPTOGAMS by <appro\@openssl.org>"
.align	2
___

$code =~ s/\bbx\s+lr\b/.word\t0xFF/gm;	# make it possible to compile with -march=armv4
$code =~ s/\bret\b/bx\tlr/gm;

open SELF,$0;
while(<SELF>) {
	next if (/^#!/);
	last if (!s/^#/@/ and !/^$/);
	print;
}
close SELF;

print $code;
close STDOUT;	# enforce flush
