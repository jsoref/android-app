#! /usr/bin/env perl
# Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. Rights for redistribution and usage in source and binary
# forms are granted according to the OpenSSL license.
# ====================================================================
#
# Version 1.1
#
# The major reason for undertaken effort was to mitigate the hazard of
# cache-timing attack. This is [currently and initially!] addressed in
# two ways. 1. S-boxes are compressed from 5KB to 2KB+256B size each.
# 2. References to them are scheduled for L2 cache latency, meaning
# that the tables don't have to reside in L1 cache. Once again, this
# is an initial draft and one should expect more countermeasures to
# be implemented...
#
# Version 1.1 prefetches T[ed]4 in order to mitigate attack on last
# round.
#
# Even though performance was not the primary goal [on the contrary,
# extra shifts "induced" by compressed S-box and longer loop epilogue
# "induced" by scheduling for L2 have negative effect on performance],
# the code turned out to run in ~23 cycles per processed byte en-/
# decrypted with 128-bit key. This is pretty good result for code
# with mentioned qualities and UltraSPARC core. Compared to Sun C
# generated code my encrypt procedure runs just few percents faster,
# while decrypt one - whole 50% faster [yes, Sun C failed to generate
# optimal decrypt procedure]. Compared to GNU C generated code both
# procedures are more than 60% faster:-)

$output = pop;
open STDOUT,">$output";

$frame="STACK_FRAME";
$bias="STACK_BIAS";
$locals=16;

$acc0="%l0";
$acc1="%o0";
$acc2="%o1";
$acc3="%o2";

$acc4="%l1";
$acc5="%o3";
$acc6="%o4";
$acc7="%o5";

$acc8="%l2";
$acc9="%o7";
$acc10="%g1";
$acc11="%g2";

$acc12="%l3";
$acc13="%g3";
$acc14="%g4";
$acc15="%g5";

$t0="%l4";
$t1="%l5";
$t2="%l6";
$t3="%l7";

$s0="%i0";
$s1="%i1";
$s2="%i2";
$s3="%i3";
$tbl="%i4";
$key="%i5";
$rounds="%i7";	# aliases with return address, which is off-loaded to stack

sub _data_word()
{ my $i;
    while(defined($i=shift)) { $code.=sprintf"\t.long\t0x%08x,0x%08x\n",$i,$i; }
}

$code.=<<___;
#include "sparc_arch.h"

#ifdef  __arch64__
.register	%g2,#scratch
.register	%g3,#scratch
#endif
.section	".text",#alloc,#execinstr

.align	256
AES_Te:
___
&_data_word(
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF);
$code.=<<___;
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
.type	AES_Te,#object
.size	AES_Te,(.-AES_Te)

.align	64
.skip	16
_sparcv9_AES_encrypt:
	save	%sp,-$frame-$locals,%sp
	stx	%i7,[%sp+$bias+$frame+0]	! off-load return address
	ld	[$key+240],$rounds
	ld	[$key+0],$t0
	ld	[$key+4],$t1			!
	ld	[$key+8],$t2
	srl	$rounds,1,$rounds
	xor	$t0,$s0,$s0
	ld	[$key+12],$t3
	srl	$s0,21,$acc0
	xor	$t1,$s1,$s1
	ld	[$key+16],$t0
	srl	$s1,13,$acc1			!
	xor	$t2,$s2,$s2
	ld	[$key+20],$t1
	xor	$t3,$s3,$s3
	ld	[$key+24],$t2
	and	$acc0,2040,$acc0
	ld	[$key+28],$t3
	nop
.Lenc_loop:
	srl	$s2,5,$acc2			!
	and	$acc1,2040,$acc1
	ldx	[$tbl+$acc0],$acc0
	sll	$s3,3,$acc3
	and	$acc2,2040,$acc2
	ldx	[$tbl+$acc1],$acc1
	srl	$s1,21,$acc4
	and	$acc3,2040,$acc3
	ldx	[$tbl+$acc2],$acc2		!
	srl	$s2,13,$acc5
	and	$acc4,2040,$acc4
	ldx	[$tbl+$acc3],$acc3
	srl	$s3,5,$acc6
	and	$acc5,2040,$acc5
	ldx	[$tbl+$acc4],$acc4
	fmovs	%f0,%f0
	sll	$s0,3,$acc7			!
	and	$acc6,2040,$acc6
	ldx	[$tbl+$acc5],$acc5
	srl	$s2,21,$acc8
	and	$acc7,2040,$acc7
	ldx	[$tbl+$acc6],$acc6
	srl	$s3,13,$acc9
	and	$acc8,2040,$acc8
	ldx	[$tbl+$acc7],$acc7		!
	srl	$s0,5,$acc10
	and	$acc9,2040,$acc9
	ldx	[$tbl+$acc8],$acc8
	sll	$s1,3,$acc11
	and	$acc10,2040,$acc10
	ldx	[$tbl+$acc9],$acc9
	fmovs	%f0,%f0
	srl	$s3,21,$acc12			!
	and	$acc11,2040,$acc11
	ldx	[$tbl+$acc10],$acc10
	srl	$s0,13,$acc13
	and	$acc12,2040,$acc12
	ldx	[$tbl+$acc11],$acc11
	srl	$s1,5,$acc14
	and	$acc13,2040,$acc13
	ldx	[$tbl+$acc12],$acc12		!
	sll	$s2,3,$acc15
	and	$acc14,2040,$acc14
	ldx	[$tbl+$acc13],$acc13
	and	$acc15,2040,$acc15
	add	$key,32,$key
	ldx	[$tbl+$acc14],$acc14
	fmovs	%f0,%f0
	subcc	$rounds,1,$rounds		!
	ldx	[$tbl+$acc15],$acc15
	bz,a,pn	%icc,.Lenc_last
	add	$tbl,2048,$rounds

		srlx	$acc1,8,$acc1
		xor	$acc0,$t0,$t0
	ld	[$key+0],$s0
	fmovs	%f0,%f0
		srlx	$acc2,16,$acc2		!
		xor	$acc1,$t0,$t0
	ld	[$key+4],$s1
		srlx	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ld	[$key+8],$s2
		srlx	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ld	[$key+12],$s3			!
		srlx	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
	fmovs	%f0,%f0
		srlx	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		srlx	$acc9,8,$acc9
		xor	$acc6,$t1,$t1
		srlx	$acc10,16,$acc10	!
		xor	$acc7,$t1,$t1
		srlx	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		srlx	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		srlx	$acc14,16,$acc14
		xor	$acc10,$t2,$t2
		srlx	$acc15,24,$acc15	!
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	srl	$t0,21,$acc0
		xor	$acc14,$t3,$t3
	srl	$t1,13,$acc1
		xor	$acc15,$t3,$t3

	and	$acc0,2040,$acc0		!
	srl	$t2,5,$acc2
	and	$acc1,2040,$acc1
	ldx	[$tbl+$acc0],$acc0
	sll	$t3,3,$acc3
	and	$acc2,2040,$acc2
	ldx	[$tbl+$acc1],$acc1
	fmovs	%f0,%f0
	srl	$t1,21,$acc4			!
	and	$acc3,2040,$acc3
	ldx	[$tbl+$acc2],$acc2
	srl	$t2,13,$acc5
	and	$acc4,2040,$acc4
	ldx	[$tbl+$acc3],$acc3
	srl	$t3,5,$acc6
	and	$acc5,2040,$acc5
	ldx	[$tbl+$acc4],$acc4		!
	sll	$t0,3,$acc7
	and	$acc6,2040,$acc6
	ldx	[$tbl+$acc5],$acc5
	srl	$t2,21,$acc8
	and	$acc7,2040,$acc7
	ldx	[$tbl+$acc6],$acc6
	fmovs	%f0,%f0
	srl	$t3,13,$acc9			!
	and	$acc8,2040,$acc8
	ldx	[$tbl+$acc7],$acc7
	srl	$t0,5,$acc10
	and	$acc9,2040,$acc9
	ldx	[$tbl+$acc8],$acc8
	sll	$t1,3,$acc11
	and	$acc10,2040,$acc10
	ldx	[$tbl+$acc9],$acc9		!
	srl	$t3,21,$acc12
	and	$acc11,2040,$acc11
	ldx	[$tbl+$acc10],$acc10
	srl	$t0,13,$acc13
	and	$acc12,2040,$acc12
	ldx	[$tbl+$acc11],$acc11
	fmovs	%f0,%f0
	srl	$t1,5,$acc14			!
	and	$acc13,2040,$acc13
	ldx	[$tbl+$acc12],$acc12
	sll	$t2,3,$acc15
	and	$acc14,2040,$acc14
	ldx	[$tbl+$acc13],$acc13
		srlx	$acc1,8,$acc1
	and	$acc15,2040,$acc15
	ldx	[$tbl+$acc14],$acc14		!

		srlx	$acc2,16,$acc2
		xor	$acc0,$s0,$s0
	ldx	[$tbl+$acc15],$acc15
		srlx	$acc3,24,$acc3
		xor	$acc1,$s0,$s0
	ld	[$key+16],$t0
	fmovs	%f0,%f0
		srlx	$acc5,8,$acc5		!
		xor	$acc2,$s0,$s0
	ld	[$key+20],$t1
		srlx	$acc6,16,$acc6
		xor	$acc3,$s0,$s0
	ld	[$key+24],$t2
		srlx	$acc7,24,$acc7
		xor	$acc4,$s1,$s1
	ld	[$key+28],$t3			!
		srlx	$acc9,8,$acc9
		xor	$acc5,$s1,$s1
	ldx	[$tbl+2048+0],%g0		! prefetch te4
		srlx	$acc10,16,$acc10
		xor	$acc6,$s1,$s1
	ldx	[$tbl+2048+32],%g0		! prefetch te4
		srlx	$acc11,24,$acc11
		xor	$acc7,$s1,$s1
	ldx	[$tbl+2048+64],%g0		! prefetch te4
		srlx	$acc13,8,$acc13
		xor	$acc8,$s2,$s2
	ldx	[$tbl+2048+96],%g0		! prefetch te4
		srlx	$acc14,16,$acc14	!
		xor	$acc9,$s2,$s2
	ldx	[$tbl+2048+128],%g0		! prefetch te4
		srlx	$acc15,24,$acc15
		xor	$acc10,$s2,$s2
	ldx	[$tbl+2048+160],%g0		! prefetch te4
	srl	$s0,21,$acc0
		xor	$acc11,$s2,$s2
	ldx	[$tbl+2048+192],%g0		! prefetch te4
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$s3,$s3
	ldx	[$tbl+2048+224],%g0		! prefetch te4
	srl	$s1,13,$acc1			!
		xor	$acc14,$s3,$s3
		xor	$acc15,$s3,$s3
	ba	.Lenc_loop
	and	$acc0,2040,$acc0

.align	32
.Lenc_last:
		srlx	$acc1,8,$acc1		!
		xor	$acc0,$t0,$t0
	ld	[$key+0],$s0
		srlx	$acc2,16,$acc2
		xor	$acc1,$t0,$t0
	ld	[$key+4],$s1
		srlx	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ld	[$key+8],$s2			!
		srlx	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ld	[$key+12],$s3
		srlx	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
		srlx	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		srlx	$acc9,8,$acc9		!
		xor	$acc6,$t1,$t1
		srlx	$acc10,16,$acc10
		xor	$acc7,$t1,$t1
		srlx	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		srlx	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		srlx	$acc14,16,$acc14	!
		xor	$acc10,$t2,$t2
		srlx	$acc15,24,$acc15
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	srl	$t0,24,$acc0
		xor	$acc14,$t3,$t3
	srl	$t1,16,$acc1			!
		xor	$acc15,$t3,$t3

	srl	$t2,8,$acc2
	and	$acc1,255,$acc1
	ldub	[$rounds+$acc0],$acc0
	srl	$t1,24,$acc4
	and	$acc2,255,$acc2
	ldub	[$rounds+$acc1],$acc1
	srl	$t2,16,$acc5			!
	and	$t3,255,$acc3
	ldub	[$rounds+$acc2],$acc2
	ldub	[$rounds+$acc3],$acc3
	srl	$t3,8,$acc6
	and	$acc5,255,$acc5
	ldub	[$rounds+$acc4],$acc4
	fmovs	%f0,%f0
	srl	$t2,24,$acc8			!
	and	$acc6,255,$acc6
	ldub	[$rounds+$acc5],$acc5
	srl	$t3,16,$acc9
	and	$t0,255,$acc7
	ldub	[$rounds+$acc6],$acc6
	ldub	[$rounds+$acc7],$acc7
	fmovs	%f0,%f0
	srl	$t0,8,$acc10			!
	and	$acc9,255,$acc9
	ldub	[$rounds+$acc8],$acc8
	srl	$t3,24,$acc12
	and	$acc10,255,$acc10
	ldub	[$rounds+$acc9],$acc9
	srl	$t0,16,$acc13
	and	$t1,255,$acc11
	ldub	[$rounds+$acc10],$acc10		!
	srl	$t1,8,$acc14
	and	$acc13,255,$acc13
	ldub	[$rounds+$acc11],$acc11
	ldub	[$rounds+$acc12],$acc12
	and	$acc14,255,$acc14
	ldub	[$rounds+$acc13],$acc13
	and	$t2,255,$acc15
	ldub	[$rounds+$acc14],$acc14		!

		sll	$acc0,24,$acc0
		xor	$acc3,$s0,$s0
	ldub	[$rounds+$acc15],$acc15
		sll	$acc1,16,$acc1
		xor	$acc0,$s0,$s0
	ldx	[%sp+$bias+$frame+0],%i7	! restore return address
	fmovs	%f0,%f0
		sll	$acc2,8,$acc2		!
		xor	$acc1,$s0,$s0
		sll	$acc4,24,$acc4
		xor	$acc2,$s0,$s0
		sll	$acc5,16,$acc5
		xor	$acc7,$s1,$s1
		sll	$acc6,8,$acc6
		xor	$acc4,$s1,$s1
		sll	$acc8,24,$acc8		!
		xor	$acc5,$s1,$s1
		sll	$acc9,16,$acc9
		xor	$acc11,$s2,$s2
		sll	$acc10,8,$acc10
		xor	$acc6,$s1,$s1
		sll	$acc12,24,$acc12
		xor	$acc8,$s2,$s2
		sll	$acc13,16,$acc13	!
		xor	$acc9,$s2,$s2
		sll	$acc14,8,$acc14
		xor	$acc10,$s2,$s2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$s3,$s3
		xor	$acc14,$s3,$s3
		xor	$acc15,$s3,$s3

	ret
	restore
.type	_sparcv9_AES_encrypt,#function
.size	_sparcv9_AES_encrypt,(.-_sparcv9_AES_encrypt)

.align	32
.globl	AES_encrypt
AES_encrypt:
	or	%o0,%o1,%g1
	andcc	%g1,3,%g0
	bnz,pn	%xcc,.Lunaligned_enc
	save	%sp,-$frame,%sp

	ld	[%i0+0],%o0
	ld	[%i0+4],%o1
	ld	[%i0+8],%o2
	ld	[%i0+12],%o3

1:	call	.+8
	add	%o7,AES_Te-1b,%o4
	call	_sparcv9_AES_encrypt
	mov	%i2,%o5

	st	%o0,[%i1+0]
	st	%o1,[%i1+4]
	st	%o2,[%i1+8]
	st	%o3,[%i1+12]

	ret
	restore

.align	32
.Lunaligned_enc:
	ldub	[%i0+0],%l0
	ldub	[%i0+1],%l1
	ldub	[%i0+2],%l2

	sll	%l0,24,%l0
	ldub	[%i0+3],%l3
	sll	%l1,16,%l1
	ldub	[%i0+4],%l4
	sll	%l2,8,%l2
	or	%l1,%l0,%l0
	ldub	[%i0+5],%l5
	sll	%l4,24,%l4
	or	%l3,%l2,%l2
	ldub	[%i0+6],%l6
	sll	%l5,16,%l5
	or	%l0,%l2,%o0
	ldub	[%i0+7],%l7

	sll	%l6,8,%l6
	or	%l5,%l4,%l4
	ldub	[%i0+8],%l0
	or	%l7,%l6,%l6
	ldub	[%i0+9],%l1
	or	%l4,%l6,%o1
	ldub	[%i0+10],%l2

	sll	%l0,24,%l0
	ldub	[%i0+11],%l3
	sll	%l1,16,%l1
	ldub	[%i0+12],%l4
	sll	%l2,8,%l2
	or	%l1,%l0,%l0
	ldub	[%i0+13],%l5
	sll	%l4,24,%l4
	or	%l3,%l2,%l2
	ldub	[%i0+14],%l6
	sll	%l5,16,%l5
	or	%l0,%l2,%o2
	ldub	[%i0+15],%l7

	sll	%l6,8,%l6
	or	%l5,%l4,%l4
	or	%l7,%l6,%l6
	or	%l4,%l6,%o3

1:	call	.+8
	add	%o7,AES_Te-1b,%o4
	call	_sparcv9_AES_encrypt
	mov	%i2,%o5

	srl	%o0,24,%l0
	srl	%o0,16,%l1
	stb	%l0,[%i1+0]
	srl	%o0,8,%l2
	stb	%l1,[%i1+1]
	stb	%l2,[%i1+2]
	srl	%o1,24,%l4
	stb	%o0,[%i1+3]

	srl	%o1,16,%l5
	stb	%l4,[%i1+4]
	srl	%o1,8,%l6
	stb	%l5,[%i1+5]
	stb	%l6,[%i1+6]
	srl	%o2,24,%l0
	stb	%o1,[%i1+7]

	srl	%o2,16,%l1
	stb	%l0,[%i1+8]
	srl	%o2,8,%l2
	stb	%l1,[%i1+9]
	stb	%l2,[%i1+10]
	srl	%o3,24,%l4
	stb	%o2,[%i1+11]

	srl	%o3,16,%l5
	stb	%l4,[%i1+12]
	srl	%o3,8,%l6
	stb	%l5,[%i1+13]
	stb	%l6,[%i1+14]
	stb	%o3,[%i1+15]

	ret
	restore
.type	AES_encrypt,#function
.size	AES_encrypt,(.-AES_encrypt)

___

$code.=<<___;
.align	256
AES_Td:
___
&_data_word(
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF);
$code.=<<___;
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
.type	AES_Td,#object
.size	AES_Td,(.-AES_Td)

.align	64
.skip	16
_sparcv9_AES_decrypt:
	save	%sp,-$frame-$locals,%sp
	stx	%i7,[%sp+$bias+$frame+0]	! off-load return address
	ld	[$key+240],$rounds
	ld	[$key+0],$t0
	ld	[$key+4],$t1			!
	ld	[$key+8],$t2
	ld	[$key+12],$t3
	srl	$rounds,1,$rounds
	xor	$t0,$s0,$s0
	ld	[$key+16],$t0
	xor	$t1,$s1,$s1
	ld	[$key+20],$t1
	srl	$s0,21,$acc0			!
	xor	$t2,$s2,$s2
	ld	[$key+24],$t2
	xor	$t3,$s3,$s3
	and	$acc0,2040,$acc0
	ld	[$key+28],$t3
	srl	$s3,13,$acc1
	nop
.Ldec_loop:
	srl	$s2,5,$acc2			!
	and	$acc1,2040,$acc1
	ldx	[$tbl+$acc0],$acc0
	sll	$s1,3,$acc3
	and	$acc2,2040,$acc2
	ldx	[$tbl+$acc1],$acc1
	srl	$s1,21,$acc4
	and	$acc3,2040,$acc3
	ldx	[$tbl+$acc2],$acc2		!
	srl	$s0,13,$acc5
	and	$acc4,2040,$acc4
	ldx	[$tbl+$acc3],$acc3
	srl	$s3,5,$acc6
	and	$acc5,2040,$acc5
	ldx	[$tbl+$acc4],$acc4
	fmovs	%f0,%f0
	sll	$s2,3,$acc7			!
	and	$acc6,2040,$acc6
	ldx	[$tbl+$acc5],$acc5
	srl	$s2,21,$acc8
	and	$acc7,2040,$acc7
	ldx	[$tbl+$acc6],$acc6
	srl	$s1,13,$acc9
	and	$acc8,2040,$acc8
	ldx	[$tbl+$acc7],$acc7		!
	srl	$s0,5,$acc10
	and	$acc9,2040,$acc9
	ldx	[$tbl+$acc8],$acc8
	sll	$s3,3,$acc11
	and	$acc10,2040,$acc10
	ldx	[$tbl+$acc9],$acc9
	fmovs	%f0,%f0
	srl	$s3,21,$acc12			!
	and	$acc11,2040,$acc11
	ldx	[$tbl+$acc10],$acc10
	srl	$s2,13,$acc13
	and	$acc12,2040,$acc12
	ldx	[$tbl+$acc11],$acc11
	srl	$s1,5,$acc14
	and	$acc13,2040,$acc13
	ldx	[$tbl+$acc12],$acc12		!
	sll	$s0,3,$acc15
	and	$acc14,2040,$acc14
	ldx	[$tbl+$acc13],$acc13
	and	$acc15,2040,$acc15
	add	$key,32,$key
	ldx	[$tbl+$acc14],$acc14
	fmovs	%f0,%f0
	subcc	$rounds,1,$rounds		!
	ldx	[$tbl+$acc15],$acc15
	bz,a,pn	%icc,.Ldec_last
	add	$tbl,2048,$rounds

		srlx	$acc1,8,$acc1
		xor	$acc0,$t0,$t0
	ld	[$key+0],$s0
	fmovs	%f0,%f0
		srlx	$acc2,16,$acc2		!
		xor	$acc1,$t0,$t0
	ld	[$key+4],$s1
		srlx	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ld	[$key+8],$s2
		srlx	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ld	[$key+12],$s3			!
		srlx	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
	fmovs	%f0,%f0
		srlx	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		srlx	$acc9,8,$acc9
		xor	$acc6,$t1,$t1
		srlx	$acc10,16,$acc10	!
		xor	$acc7,$t1,$t1
		srlx	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		srlx	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		srlx	$acc14,16,$acc14
		xor	$acc10,$t2,$t2
		srlx	$acc15,24,$acc15	!
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	srl	$t0,21,$acc0
		xor	$acc14,$t3,$t3
		xor	$acc15,$t3,$t3
	srl	$t3,13,$acc1

	and	$acc0,2040,$acc0		!
	srl	$t2,5,$acc2
	and	$acc1,2040,$acc1
	ldx	[$tbl+$acc0],$acc0
	sll	$t1,3,$acc3
	and	$acc2,2040,$acc2
	ldx	[$tbl+$acc1],$acc1
	fmovs	%f0,%f0
	srl	$t1,21,$acc4			!
	and	$acc3,2040,$acc3
	ldx	[$tbl+$acc2],$acc2
	srl	$t0,13,$acc5
	and	$acc4,2040,$acc4
	ldx	[$tbl+$acc3],$acc3
	srl	$t3,5,$acc6
	and	$acc5,2040,$acc5
	ldx	[$tbl+$acc4],$acc4		!
	sll	$t2,3,$acc7
	and	$acc6,2040,$acc6
	ldx	[$tbl+$acc5],$acc5
	srl	$t2,21,$acc8
	and	$acc7,2040,$acc7
	ldx	[$tbl+$acc6],$acc6
	fmovs	%f0,%f0
	srl	$t1,13,$acc9			!
	and	$acc8,2040,$acc8
	ldx	[$tbl+$acc7],$acc7
	srl	$t0,5,$acc10
	and	$acc9,2040,$acc9
	ldx	[$tbl+$acc8],$acc8
	sll	$t3,3,$acc11
	and	$acc10,2040,$acc10
	ldx	[$tbl+$acc9],$acc9		!
	srl	$t3,21,$acc12
	and	$acc11,2040,$acc11
	ldx	[$tbl+$acc10],$acc10
	srl	$t2,13,$acc13
	and	$acc12,2040,$acc12
	ldx	[$tbl+$acc11],$acc11
	fmovs	%f0,%f0
	srl	$t1,5,$acc14			!
	and	$acc13,2040,$acc13
	ldx	[$tbl+$acc12],$acc12
	sll	$t0,3,$acc15
	and	$acc14,2040,$acc14
	ldx	[$tbl+$acc13],$acc13
		srlx	$acc1,8,$acc1
	and	$acc15,2040,$acc15
	ldx	[$tbl+$acc14],$acc14		!

		srlx	$acc2,16,$acc2
		xor	$acc0,$s0,$s0
	ldx	[$tbl+$acc15],$acc15
		srlx	$acc3,24,$acc3
		xor	$acc1,$s0,$s0
	ld	[$key+16],$t0
	fmovs	%f0,%f0
		srlx	$acc5,8,$acc5		!
		xor	$acc2,$s0,$s0
	ld	[$key+20],$t1
		srlx	$acc6,16,$acc6
		xor	$acc3,$s0,$s0
	ld	[$key+24],$t2
		srlx	$acc7,24,$acc7
		xor	$acc4,$s1,$s1
	ld	[$key+28],$t3			!
		srlx	$acc9,8,$acc9
		xor	$acc5,$s1,$s1
	ldx	[$tbl+2048+0],%g0		! prefetch td4
		srlx	$acc10,16,$acc10
		xor	$acc6,$s1,$s1
	ldx	[$tbl+2048+32],%g0		! prefetch td4
		srlx	$acc11,24,$acc11
		xor	$acc7,$s1,$s1
	ldx	[$tbl+2048+64],%g0		! prefetch td4
		srlx	$acc13,8,$acc13
		xor	$acc8,$s2,$s2
	ldx	[$tbl+2048+96],%g0		! prefetch td4
		srlx	$acc14,16,$acc14	!
		xor	$acc9,$s2,$s2
	ldx	[$tbl+2048+128],%g0		! prefetch td4
		srlx	$acc15,24,$acc15
		xor	$acc10,$s2,$s2
	ldx	[$tbl+2048+160],%g0		! prefetch td4
	srl	$s0,21,$acc0
		xor	$acc11,$s2,$s2
	ldx	[$tbl+2048+192],%g0		! prefetch td4
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$s3,$s3
	ldx	[$tbl+2048+224],%g0		! prefetch td4
	and	$acc0,2040,$acc0		!
		xor	$acc14,$s3,$s3
		xor	$acc15,$s3,$s3
	ba	.Ldec_loop
	srl	$s3,13,$acc1

.align	32
.Ldec_last:
		srlx	$acc1,8,$acc1		!
		xor	$acc0,$t0,$t0
	ld	[$key+0],$s0
		srlx	$acc2,16,$acc2
		xor	$acc1,$t0,$t0
	ld	[$key+4],$s1
		srlx	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ld	[$key+8],$s2			!
		srlx	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ld	[$key+12],$s3
		srlx	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
		srlx	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		srlx	$acc9,8,$acc9		!
		xor	$acc6,$t1,$t1
		srlx	$acc10,16,$acc10
		xor	$acc7,$t1,$t1
		srlx	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		srlx	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		srlx	$acc14,16,$acc14	!
		xor	$acc10,$t2,$t2
		srlx	$acc15,24,$acc15
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	srl	$t0,24,$acc0
		xor	$acc14,$t3,$t3
		xor	$acc15,$t3,$t3		!
	srl	$t3,16,$acc1

	srl	$t2,8,$acc2
	and	$acc1,255,$acc1
	ldub	[$rounds+$acc0],$acc0
	srl	$t1,24,$acc4
	and	$acc2,255,$acc2
	ldub	[$rounds+$acc1],$acc1
	srl	$t0,16,$acc5			!
	and	$t1,255,$acc3
	ldub	[$rounds+$acc2],$acc2
	ldub	[$rounds+$acc3],$acc3
	srl	$t3,8,$acc6
	and	$acc5,255,$acc5
	ldub	[$rounds+$acc4],$acc4
	fmovs	%f0,%f0
	srl	$t2,24,$acc8			!
	and	$acc6,255,$acc6
	ldub	[$rounds+$acc5],$acc5
	srl	$t1,16,$acc9
	and	$t2,255,$acc7
	ldub	[$rounds+$acc6],$acc6
	ldub	[$rounds+$acc7],$acc7
	fmovs	%f0,%f0
	srl	$t0,8,$acc10			!
	and	$acc9,255,$acc9
	ldub	[$rounds+$acc8],$acc8
	srl	$t3,24,$acc12
	and	$acc10,255,$acc10
	ldub	[$rounds+$acc9],$acc9
	srl	$t2,16,$acc13
	and	$t3,255,$acc11
	ldub	[$rounds+$acc10],$acc10		!
	srl	$t1,8,$acc14
	and	$acc13,255,$acc13
	ldub	[$rounds+$acc11],$acc11
	ldub	[$rounds+$acc12],$acc12
	and	$acc14,255,$acc14
	ldub	[$rounds+$acc13],$acc13
	and	$t0,255,$acc15
	ldub	[$rounds+$acc14],$acc14		!

		sll	$acc0,24,$acc0
		xor	$acc3,$s0,$s0
	ldub	[$rounds+$acc15],$acc15
		sll	$acc1,16,$acc1
		xor	$acc0,$s0,$s0
	ldx	[%sp+$bias+$frame+0],%i7	! restore return address
	fmovs	%f0,%f0
		sll	$acc2,8,$acc2		!
		xor	$acc1,$s0,$s0
		sll	$acc4,24,$acc4
		xor	$acc2,$s0,$s0
		sll	$acc5,16,$acc5
		xor	$acc7,$s1,$s1
		sll	$acc6,8,$acc6
		xor	$acc4,$s1,$s1
		sll	$acc8,24,$acc8		!
		xor	$acc5,$s1,$s1
		sll	$acc9,16,$acc9
		xor	$acc11,$s2,$s2
		sll	$acc10,8,$acc10
		xor	$acc6,$s1,$s1
		sll	$acc12,24,$acc12
		xor	$acc8,$s2,$s2
		sll	$acc13,16,$acc13	!
		xor	$acc9,$s2,$s2
		sll	$acc14,8,$acc14
		xor	$acc10,$s2,$s2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$s3,$s3
		xor	$acc14,$s3,$s3
		xor	$acc15,$s3,$s3

	ret
	restore
.type	_sparcv9_AES_decrypt,#function
.size	_sparcv9_AES_decrypt,(.-_sparcv9_AES_decrypt)

.align	32
.globl	AES_decrypt
AES_decrypt:
	or	%o0,%o1,%g1
	andcc	%g1,3,%g0
	bnz,pn	%xcc,.Lunaligned_dec
	save	%sp,-$frame,%sp

	ld	[%i0+0],%o0
	ld	[%i0+4],%o1
	ld	[%i0+8],%o2
	ld	[%i0+12],%o3

1:	call	.+8
	add	%o7,AES_Td-1b,%o4
	call	_sparcv9_AES_decrypt
	mov	%i2,%o5

	st	%o0,[%i1+0]
	st	%o1,[%i1+4]
	st	%o2,[%i1+8]
	st	%o3,[%i1+12]

	ret
	restore

.align	32
.Lunaligned_dec:
	ldub	[%i0+0],%l0
	ldub	[%i0+1],%l1
	ldub	[%i0+2],%l2

	sll	%l0,24,%l0
	ldub	[%i0+3],%l3
	sll	%l1,16,%l1
	ldub	[%i0+4],%l4
	sll	%l2,8,%l2
	or	%l1,%l0,%l0
	ldub	[%i0+5],%l5
	sll	%l4,24,%l4
	or	%l3,%l2,%l2
	ldub	[%i0+6],%l6
	sll	%l5,16,%l5
	or	%l0,%l2,%o0
	ldub	[%i0+7],%l7

	sll	%l6,8,%l6
	or	%l5,%l4,%l4
	ldub	[%i0+8],%l0
	or	%l7,%l6,%l6
	ldub	[%i0+9],%l1
	or	%l4,%l6,%o1
	ldub	[%i0+10],%l2

	sll	%l0,24,%l0
	ldub	[%i0+11],%l3
	sll	%l1,16,%l1
	ldub	[%i0+12],%l4
	sll	%l2,8,%l2
	or	%l1,%l0,%l0
	ldub	[%i0+13],%l5
	sll	%l4,24,%l4
	or	%l3,%l2,%l2
	ldub	[%i0+14],%l6
	sll	%l5,16,%l5
	or	%l0,%l2,%o2
	ldub	[%i0+15],%l7

	sll	%l6,8,%l6
	or	%l5,%l4,%l4
	or	%l7,%l6,%l6
	or	%l4,%l6,%o3

1:	call	.+8
	add	%o7,AES_Td-1b,%o4
	call	_sparcv9_AES_decrypt
	mov	%i2,%o5

	srl	%o0,24,%l0
	srl	%o0,16,%l1
	stb	%l0,[%i1+0]
	srl	%o0,8,%l2
	stb	%l1,[%i1+1]
	stb	%l2,[%i1+2]
	srl	%o1,24,%l4
	stb	%o0,[%i1+3]

	srl	%o1,16,%l5
	stb	%l4,[%i1+4]
	srl	%o1,8,%l6
	stb	%l5,[%i1+5]
	stb	%l6,[%i1+6]
	srl	%o2,24,%l0
	stb	%o1,[%i1+7]

	srl	%o2,16,%l1
	stb	%l0,[%i1+8]
	srl	%o2,8,%l2
	stb	%l1,[%i1+9]
	stb	%l2,[%i1+10]
	srl	%o3,24,%l4
	stb	%o2,[%i1+11]

	srl	%o3,16,%l5
	stb	%l4,[%i1+12]
	srl	%o3,8,%l6
	stb	%l5,[%i1+13]
	stb	%l6,[%i1+14]
	stb	%o3,[%i1+15]

	ret
	restore
.type	AES_decrypt,#function
.size	AES_decrypt,(.-AES_decrypt)
___

# fmovs instructions substituting for FP nops were originally added
# to meet specific instruction alignment requirements to maximize ILP.
# As UltraSPARC T1, a.k.a. Niagara, has shared FPU, FP nops can have
# undesired effect, so just omit them and sacrifice some portion of
# percent in performance...
$code =~ s/fmovs.*$//gm;

print $code;
close STDOUT;	# ensure flush
