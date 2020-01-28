#! /usr/bin/env perl
# Copyright 2009-2018 The OpenSSL Project Authors. All Rights Reserved.
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

# AES for PA-RISC.
#
# June 2009.
#
# The module is mechanical transliteration of aes-sparcv9.pl, but with
# a twist: S-boxes are compressed even further down to 1K+256B. On
# PA-7100LC performance is ~40% better than gcc 3.2 generated code and
# is about 33 cycles per byte processed with 128-bit key. Newer CPUs
# perform at 16 cycles per byte. It's not faster than code generated
# by vendor compiler, but recall that it has compressed S-boxes, which
# requires extra processing.
#
# Special thanks to polarhome.com for providing HP-UX account.

$flavour = shift;
$output = shift;
open STDOUT,">$output";

if ($flavour =~ /64/) {
	$LEVEL		="2.0W";
	$SIZE_T		=8;
	$FRAME_MARKER	=80;
	$SAVED_RP	=16;
	$PUSH		="std";
	$PUSHMA		="std,ma";
	$POP		="ldd";
	$POPMB		="ldd,mb";
} else {
	$LEVEL		="1.0";
	$SIZE_T		=4;
	$FRAME_MARKER	=48;
	$SAVED_RP	=20;
	$PUSH		="stw";
	$PUSHMA		="stwm";
	$POP		="ldw";
	$POPMB		="ldwm";
}

$FRAME=16*$SIZE_T+$FRAME_MARKER;# 16 saved regs + frame marker
				#                 [+ argument transfer]
$inp="%r26";	# arg0
$out="%r25";	# arg1
$key="%r24";	# arg2

($s0,$s1,$s2,$s3) = ("%r1","%r2","%r3","%r4");
($t0,$t1,$t2,$t3) = ("%r5","%r6","%r7","%r8");

($acc0, $acc1, $acc2, $acc3, $acc4, $acc5, $acc6, $acc7,
 $acc8, $acc9,$acc10,$acc11,$acc12,$acc13,$acc14,$acc15) =
("%r9","%r10","%r11","%r12","%r13","%r14","%r15","%r16",
"%r17","%r18","%r19","%r20","%r21","%r22","%r23","%r26");

$tbl="%r28";
$rounds="%r29";

$code=<<___;
	.LEVEL	$LEVEL
	.SPACE	\$TEXT\$
	.SUBSPA	\$CODE\$,QUAD=0,ALIGN=8,ACCESS=0xFF,CODE_ONLY

	.EXPORT	AES_encrypt,ENTRY,ARGW0=GR,ARGW1=GR,ARGW2=GR
	.ALIGN	64
AES_encrypt
	.PROC
	.CALLINFO	FRAME=`$FRAME-16*$SIZE_T`,NO_CALLS,SAVE_RP,ENTRY_GR=18
	.ENTRY
	$PUSH	%r2,-$SAVED_RP(%sp)	; standard prologue
	$PUSHMA	%r3,$FRAME(%sp)
	$PUSH	%r4,`-$FRAME+1*$SIZE_T`(%sp)
	$PUSH	%r5,`-$FRAME+2*$SIZE_T`(%sp)
	$PUSH	%r6,`-$FRAME+3*$SIZE_T`(%sp)
	$PUSH	%r7,`-$FRAME+4*$SIZE_T`(%sp)
	$PUSH	%r8,`-$FRAME+5*$SIZE_T`(%sp)
	$PUSH	%r9,`-$FRAME+6*$SIZE_T`(%sp)
	$PUSH	%r10,`-$FRAME+7*$SIZE_T`(%sp)
	$PUSH	%r11,`-$FRAME+8*$SIZE_T`(%sp)
	$PUSH	%r12,`-$FRAME+9*$SIZE_T`(%sp)
	$PUSH	%r13,`-$FRAME+10*$SIZE_T`(%sp)
	$PUSH	%r14,`-$FRAME+11*$SIZE_T`(%sp)
	$PUSH	%r15,`-$FRAME+12*$SIZE_T`(%sp)
	$PUSH	%r16,`-$FRAME+13*$SIZE_T`(%sp)
	$PUSH	%r17,`-$FRAME+14*$SIZE_T`(%sp)
	$PUSH	%r18,`-$FRAME+15*$SIZE_T`(%sp)

	blr	%r0,$tbl
	ldi	3,$t0
L\$enc_pic
	andcm	$tbl,$t0,$tbl
	ldo	L\$AES_Te-L\$enc_pic($tbl),$tbl

	and	$inp,$t0,$t0
	sub	$inp,$t0,$inp
	ldw	0($inp),$s0
	ldw	4($inp),$s1
	ldw	8($inp),$s2
	comib,=	0,$t0,L\$enc_inp_aligned
	ldw	12($inp),$s3

	sh3addl	$t0,%r0,$t0
	subi	32,$t0,$t0
	mtctl	$t0,%cr11
	ldw	16($inp),$t1
	vshd	$s0,$s1,$s0
	vshd	$s1,$s2,$s1
	vshd	$s2,$s3,$s2
	vshd	$s3,$t1,$s3

L\$enc_inp_aligned
	bl	_parisc_AES_encrypt,%r31
	nop

	extru,<> $out,31,2,%r0
	b	L\$enc_out_aligned
	nop

	_srm	$s0,24,$acc0
	_srm	$s0,16,$acc1
	stb	$acc0,0($out)
	_srm	$s0,8,$acc2
	stb	$acc1,1($out)
	_srm	$s1,24,$acc4
	stb	$acc2,2($out)
	_srm	$s1,16,$acc5
	stb	$s0,3($out)
	_srm	$s1,8,$acc6
	stb	$acc4,4($out)
	_srm	$s2,24,$acc0
	stb	$acc5,5($out)
	_srm	$s2,16,$acc1
	stb	$acc6,6($out)
	_srm	$s2,8,$acc2
	stb	$s1,7($out)
	_srm	$s3,24,$acc4
	stb	$acc0,8($out)
	_srm	$s3,16,$acc5
	stb	$acc1,9($out)
	_srm	$s3,8,$acc6
	stb	$acc2,10($out)
	stb	$s2,11($out)
	stb	$acc4,12($out)
	stb	$acc5,13($out)
	stb	$acc6,14($out)
	b	L\$enc_done
	stb	$s3,15($out)

L\$enc_out_aligned
	stw	$s0,0($out)
	stw	$s1,4($out)
	stw	$s2,8($out)
	stw	$s3,12($out)

L\$enc_done
	$POP	`-$FRAME-$SAVED_RP`(%sp),%r2	; standard epilogue
	$POP	`-$FRAME+1*$SIZE_T`(%sp),%r4
	$POP	`-$FRAME+2*$SIZE_T`(%sp),%r5
	$POP	`-$FRAME+3*$SIZE_T`(%sp),%r6
	$POP	`-$FRAME+4*$SIZE_T`(%sp),%r7
	$POP	`-$FRAME+5*$SIZE_T`(%sp),%r8
	$POP	`-$FRAME+6*$SIZE_T`(%sp),%r9
	$POP	`-$FRAME+7*$SIZE_T`(%sp),%r10
	$POP	`-$FRAME+8*$SIZE_T`(%sp),%r11
	$POP	`-$FRAME+9*$SIZE_T`(%sp),%r12
	$POP	`-$FRAME+10*$SIZE_T`(%sp),%r13
	$POP	`-$FRAME+11*$SIZE_T`(%sp),%r14
	$POP	`-$FRAME+12*$SIZE_T`(%sp),%r15
	$POP	`-$FRAME+13*$SIZE_T`(%sp),%r16
	$POP	`-$FRAME+14*$SIZE_T`(%sp),%r17
	$POP	`-$FRAME+15*$SIZE_T`(%sp),%r18
	bv	(%r2)
	.EXIT
	$POPMB	-$FRAME(%sp),%r3
	.PROCEND

	.ALIGN	16
_parisc_AES_encrypt
	.PROC
	.CALLINFO	MILLICODE
	.ENTRY
	ldw	240($key),$rounds
	ldw	0($key),$t0
	ldw	4($key),$t1
	ldw	8($key),$t2
	_srm	$rounds,1,$rounds
	xor	$t0,$s0,$s0
	ldw	12($key),$t3
	_srm	$s0,24,$acc0
	xor	$t1,$s1,$s1
	ldw	16($key),$t0
	_srm	$s1,16,$acc1
	xor	$t2,$s2,$s2
	ldw	20($key),$t1
	xor	$t3,$s3,$s3
	ldw	24($key),$t2
	ldw	28($key),$t3
L\$enc_loop
	_srm	$s2,8,$acc2
	ldwx,s	$acc0($tbl),$acc0
	_srm	$s3,0,$acc3
	ldwx,s	$acc1($tbl),$acc1
	_srm	$s1,24,$acc4
	ldwx,s	$acc2($tbl),$acc2
	_srm	$s2,16,$acc5
	ldwx,s	$acc3($tbl),$acc3
	_srm	$s3,8,$acc6
	ldwx,s	$acc4($tbl),$acc4
	_srm	$s0,0,$acc7
	ldwx,s	$acc5($tbl),$acc5
	_srm	$s2,24,$acc8
	ldwx,s	$acc6($tbl),$acc6
	_srm	$s3,16,$acc9
	ldwx,s	$acc7($tbl),$acc7
	_srm	$s0,8,$acc10
	ldwx,s	$acc8($tbl),$acc8
	_srm	$s1,0,$acc11
	ldwx,s	$acc9($tbl),$acc9
	_srm	$s3,24,$acc12
	ldwx,s	$acc10($tbl),$acc10
	_srm	$s0,16,$acc13
	ldwx,s	$acc11($tbl),$acc11
	_srm	$s1,8,$acc14
	ldwx,s	$acc12($tbl),$acc12
	_srm	$s2,0,$acc15
	ldwx,s	$acc13($tbl),$acc13
	ldwx,s	$acc14($tbl),$acc14
	ldwx,s	$acc15($tbl),$acc15
	addib,= -1,$rounds,L\$enc_last
	ldo	32($key),$key

		_ror	$acc1,8,$acc1
		xor	$acc0,$t0,$t0
	ldw	0($key),$s0
		_ror	$acc2,16,$acc2
		xor	$acc1,$t0,$t0
	ldw	4($key),$s1
		_ror	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ldw	8($key),$s2
		_ror	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ldw	12($key),$s3
		_ror	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
		_ror	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		_ror	$acc9,8,$acc9
		xor	$acc6,$t1,$t1
		_ror	$acc10,16,$acc10
		xor	$acc7,$t1,$t1
		_ror	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		_ror	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		_ror	$acc14,16,$acc14
		xor	$acc10,$t2,$t2
		_ror	$acc15,24,$acc15
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	_srm	$t0,24,$acc0
		xor	$acc14,$t3,$t3
	_srm	$t1,16,$acc1
		xor	$acc15,$t3,$t3

	_srm	$t2,8,$acc2
	ldwx,s	$acc0($tbl),$acc0
	_srm	$t3,0,$acc3
	ldwx,s	$acc1($tbl),$acc1
	_srm	$t1,24,$acc4
	ldwx,s	$acc2($tbl),$acc2
	_srm	$t2,16,$acc5
	ldwx,s	$acc3($tbl),$acc3
	_srm	$t3,8,$acc6
	ldwx,s	$acc4($tbl),$acc4
	_srm	$t0,0,$acc7
	ldwx,s	$acc5($tbl),$acc5
	_srm	$t2,24,$acc8
	ldwx,s	$acc6($tbl),$acc6
	_srm	$t3,16,$acc9
	ldwx,s	$acc7($tbl),$acc7
	_srm	$t0,8,$acc10
	ldwx,s	$acc8($tbl),$acc8
	_srm	$t1,0,$acc11
	ldwx,s	$acc9($tbl),$acc9
	_srm	$t3,24,$acc12
	ldwx,s	$acc10($tbl),$acc10
	_srm	$t0,16,$acc13
	ldwx,s	$acc11($tbl),$acc11
	_srm	$t1,8,$acc14
	ldwx,s	$acc12($tbl),$acc12
	_srm	$t2,0,$acc15
	ldwx,s	$acc13($tbl),$acc13
		_ror	$acc1,8,$acc1
	ldwx,s	$acc14($tbl),$acc14

		_ror	$acc2,16,$acc2
		xor	$acc0,$s0,$s0
	ldwx,s	$acc15($tbl),$acc15
		_ror	$acc3,24,$acc3
		xor	$acc1,$s0,$s0
	ldw	16($key),$t0
		_ror	$acc5,8,$acc5
		xor	$acc2,$s0,$s0
	ldw	20($key),$t1
		_ror	$acc6,16,$acc6
		xor	$acc3,$s0,$s0
	ldw	24($key),$t2
		_ror	$acc7,24,$acc7
		xor	$acc4,$s1,$s1
	ldw	28($key),$t3
		_ror	$acc9,8,$acc9
		xor	$acc5,$s1,$s1
	ldw	1024+0($tbl),%r0		; prefetch te4
		_ror	$acc10,16,$acc10
		xor	$acc6,$s1,$s1
	ldw	1024+32($tbl),%r0		; prefetch te4
		_ror	$acc11,24,$acc11
		xor	$acc7,$s1,$s1
	ldw	1024+64($tbl),%r0		; prefetch te4
		_ror	$acc13,8,$acc13
		xor	$acc8,$s2,$s2
	ldw	1024+96($tbl),%r0		; prefetch te4
		_ror	$acc14,16,$acc14
		xor	$acc9,$s2,$s2
	ldw	1024+128($tbl),%r0		; prefetch te4
		_ror	$acc15,24,$acc15
		xor	$acc10,$s2,$s2
	ldw	1024+160($tbl),%r0		; prefetch te4
	_srm	$s0,24,$acc0
		xor	$acc11,$s2,$s2
	ldw	1024+192($tbl),%r0		; prefetch te4
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$s3,$s3
	ldw	1024+224($tbl),%r0		; prefetch te4
	_srm	$s1,16,$acc1
		xor	$acc14,$s3,$s3
	b	L\$enc_loop
		xor	$acc15,$s3,$s3

	.ALIGN	16
L\$enc_last
	ldo	1024($tbl),$rounds
		_ror	$acc1,8,$acc1
		xor	$acc0,$t0,$t0
	ldw	0($key),$s0
		_ror	$acc2,16,$acc2
		xor	$acc1,$t0,$t0
	ldw	4($key),$s1
		_ror	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ldw	8($key),$s2
		_ror	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ldw	12($key),$s3
		_ror	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
		_ror	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		_ror	$acc9,8,$acc9
		xor	$acc6,$t1,$t1
		_ror	$acc10,16,$acc10
		xor	$acc7,$t1,$t1
		_ror	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		_ror	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		_ror	$acc14,16,$acc14
		xor	$acc10,$t2,$t2
		_ror	$acc15,24,$acc15
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	_srm	$t0,24,$acc0
		xor	$acc14,$t3,$t3
	_srm	$t1,16,$acc1
		xor	$acc15,$t3,$t3

	_srm	$t2,8,$acc2
	ldbx	$acc0($rounds),$acc0
	_srm	$t1,24,$acc4
	ldbx	$acc1($rounds),$acc1
	_srm	$t2,16,$acc5
	_srm	$t3,0,$acc3
	ldbx	$acc2($rounds),$acc2
	ldbx	$acc3($rounds),$acc3
	_srm	$t3,8,$acc6
	ldbx	$acc4($rounds),$acc4
	_srm	$t2,24,$acc8
	ldbx	$acc5($rounds),$acc5
	_srm	$t3,16,$acc9
	_srm	$t0,0,$acc7
	ldbx	$acc6($rounds),$acc6
	ldbx	$acc7($rounds),$acc7
	_srm	$t0,8,$acc10
	ldbx	$acc8($rounds),$acc8
	_srm	$t3,24,$acc12
	ldbx	$acc9($rounds),$acc9
	_srm	$t0,16,$acc13
	_srm	$t1,0,$acc11
	ldbx	$acc10($rounds),$acc10
	_srm	$t1,8,$acc14
	ldbx	$acc11($rounds),$acc11
	ldbx	$acc12($rounds),$acc12
	ldbx	$acc13($rounds),$acc13
	_srm	$t2,0,$acc15
	ldbx	$acc14($rounds),$acc14

		dep	$acc0,7,8,$acc3
	ldbx	$acc15($rounds),$acc15
		dep	$acc4,7,8,$acc7
		dep	$acc1,15,8,$acc3
		dep	$acc5,15,8,$acc7
		dep	$acc2,23,8,$acc3
		dep	$acc6,23,8,$acc7
		xor	$acc3,$s0,$s0
		xor	$acc7,$s1,$s1
		dep	$acc8,7,8,$acc11
		dep	$acc12,7,8,$acc15
		dep	$acc9,15,8,$acc11
		dep	$acc13,15,8,$acc15
		dep	$acc10,23,8,$acc11
		dep	$acc14,23,8,$acc15
		xor	$acc11,$s2,$s2

	bv	(%r31)
	.EXIT
		xor	$acc15,$s3,$s3
	.PROCEND

	.ALIGN	64
L\$AES_Te
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
___

$code.=<<___;
	.EXPORT	AES_decrypt,ENTRY,ARGW0=GR,ARGW1=GR,ARGW2=GR
	.ALIGN	16
AES_decrypt
	.PROC
	.CALLINFO	FRAME=`$FRAME-16*$SIZE_T`,NO_CALLS,SAVE_RP,ENTRY_GR=18
	.ENTRY
	$PUSH	%r2,-$SAVED_RP(%sp)	; standard prologue
	$PUSHMA	%r3,$FRAME(%sp)
	$PUSH	%r4,`-$FRAME+1*$SIZE_T`(%sp)
	$PUSH	%r5,`-$FRAME+2*$SIZE_T`(%sp)
	$PUSH	%r6,`-$FRAME+3*$SIZE_T`(%sp)
	$PUSH	%r7,`-$FRAME+4*$SIZE_T`(%sp)
	$PUSH	%r8,`-$FRAME+5*$SIZE_T`(%sp)
	$PUSH	%r9,`-$FRAME+6*$SIZE_T`(%sp)
	$PUSH	%r10,`-$FRAME+7*$SIZE_T`(%sp)
	$PUSH	%r11,`-$FRAME+8*$SIZE_T`(%sp)
	$PUSH	%r12,`-$FRAME+9*$SIZE_T`(%sp)
	$PUSH	%r13,`-$FRAME+10*$SIZE_T`(%sp)
	$PUSH	%r14,`-$FRAME+11*$SIZE_T`(%sp)
	$PUSH	%r15,`-$FRAME+12*$SIZE_T`(%sp)
	$PUSH	%r16,`-$FRAME+13*$SIZE_T`(%sp)
	$PUSH	%r17,`-$FRAME+14*$SIZE_T`(%sp)
	$PUSH	%r18,`-$FRAME+15*$SIZE_T`(%sp)

	blr	%r0,$tbl
	ldi	3,$t0
L\$dec_pic
	andcm	$tbl,$t0,$tbl
	ldo	L\$AES_Td-L\$dec_pic($tbl),$tbl

	and	$inp,$t0,$t0
	sub	$inp,$t0,$inp
	ldw	0($inp),$s0
	ldw	4($inp),$s1
	ldw	8($inp),$s2
	comib,=	0,$t0,L\$dec_inp_aligned
	ldw	12($inp),$s3

	sh3addl	$t0,%r0,$t0
	subi	32,$t0,$t0
	mtctl	$t0,%cr11
	ldw	16($inp),$t1
	vshd	$s0,$s1,$s0
	vshd	$s1,$s2,$s1
	vshd	$s2,$s3,$s2
	vshd	$s3,$t1,$s3

L\$dec_inp_aligned
	bl	_parisc_AES_decrypt,%r31
	nop

	extru,<> $out,31,2,%r0
	b	L\$dec_out_aligned
	nop

	_srm	$s0,24,$acc0
	_srm	$s0,16,$acc1
	stb	$acc0,0($out)
	_srm	$s0,8,$acc2
	stb	$acc1,1($out)
	_srm	$s1,24,$acc4
	stb	$acc2,2($out)
	_srm	$s1,16,$acc5
	stb	$s0,3($out)
	_srm	$s1,8,$acc6
	stb	$acc4,4($out)
	_srm	$s2,24,$acc0
	stb	$acc5,5($out)
	_srm	$s2,16,$acc1
	stb	$acc6,6($out)
	_srm	$s2,8,$acc2
	stb	$s1,7($out)
	_srm	$s3,24,$acc4
	stb	$acc0,8($out)
	_srm	$s3,16,$acc5
	stb	$acc1,9($out)
	_srm	$s3,8,$acc6
	stb	$acc2,10($out)
	stb	$s2,11($out)
	stb	$acc4,12($out)
	stb	$acc5,13($out)
	stb	$acc6,14($out)
	b	L\$dec_done
	stb	$s3,15($out)

L\$dec_out_aligned
	stw	$s0,0($out)
	stw	$s1,4($out)
	stw	$s2,8($out)
	stw	$s3,12($out)

L\$dec_done
	$POP	`-$FRAME-$SAVED_RP`(%sp),%r2	; standard epilogue
	$POP	`-$FRAME+1*$SIZE_T`(%sp),%r4
	$POP	`-$FRAME+2*$SIZE_T`(%sp),%r5
	$POP	`-$FRAME+3*$SIZE_T`(%sp),%r6
	$POP	`-$FRAME+4*$SIZE_T`(%sp),%r7
	$POP	`-$FRAME+5*$SIZE_T`(%sp),%r8
	$POP	`-$FRAME+6*$SIZE_T`(%sp),%r9
	$POP	`-$FRAME+7*$SIZE_T`(%sp),%r10
	$POP	`-$FRAME+8*$SIZE_T`(%sp),%r11
	$POP	`-$FRAME+9*$SIZE_T`(%sp),%r12
	$POP	`-$FRAME+10*$SIZE_T`(%sp),%r13
	$POP	`-$FRAME+11*$SIZE_T`(%sp),%r14
	$POP	`-$FRAME+12*$SIZE_T`(%sp),%r15
	$POP	`-$FRAME+13*$SIZE_T`(%sp),%r16
	$POP	`-$FRAME+14*$SIZE_T`(%sp),%r17
	$POP	`-$FRAME+15*$SIZE_T`(%sp),%r18
	bv	(%r2)
	.EXIT
	$POPMB	-$FRAME(%sp),%r3
	.PROCEND

	.ALIGN	16
_parisc_AES_decrypt
	.PROC
	.CALLINFO	MILLICODE
	.ENTRY
	ldw	240($key),$rounds
	ldw	0($key),$t0
	ldw	4($key),$t1
	ldw	8($key),$t2
	ldw	12($key),$t3
	_srm	$rounds,1,$rounds
	xor	$t0,$s0,$s0
	ldw	16($key),$t0
	xor	$t1,$s1,$s1
	ldw	20($key),$t1
	_srm	$s0,24,$acc0
	xor	$t2,$s2,$s2
	ldw	24($key),$t2
	xor	$t3,$s3,$s3
	ldw	28($key),$t3
	_srm	$s3,16,$acc1
L\$dec_loop
	_srm	$s2,8,$acc2
	ldwx,s	$acc0($tbl),$acc0
	_srm	$s1,0,$acc3
	ldwx,s	$acc1($tbl),$acc1
	_srm	$s1,24,$acc4
	ldwx,s	$acc2($tbl),$acc2
	_srm	$s0,16,$acc5
	ldwx,s	$acc3($tbl),$acc3
	_srm	$s3,8,$acc6
	ldwx,s	$acc4($tbl),$acc4
	_srm	$s2,0,$acc7
	ldwx,s	$acc5($tbl),$acc5
	_srm	$s2,24,$acc8
	ldwx,s	$acc6($tbl),$acc6
	_srm	$s1,16,$acc9
	ldwx,s	$acc7($tbl),$acc7
	_srm	$s0,8,$acc10
	ldwx,s	$acc8($tbl),$acc8
	_srm	$s3,0,$acc11
	ldwx,s	$acc9($tbl),$acc9
	_srm	$s3,24,$acc12
	ldwx,s	$acc10($tbl),$acc10
	_srm	$s2,16,$acc13
	ldwx,s	$acc11($tbl),$acc11
	_srm	$s1,8,$acc14
	ldwx,s	$acc12($tbl),$acc12
	_srm	$s0,0,$acc15
	ldwx,s	$acc13($tbl),$acc13
	ldwx,s	$acc14($tbl),$acc14
	ldwx,s	$acc15($tbl),$acc15
	addib,= -1,$rounds,L\$dec_last
	ldo	32($key),$key

		_ror	$acc1,8,$acc1
		xor	$acc0,$t0,$t0
	ldw	0($key),$s0
		_ror	$acc2,16,$acc2
		xor	$acc1,$t0,$t0
	ldw	4($key),$s1
		_ror	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ldw	8($key),$s2
		_ror	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ldw	12($key),$s3
		_ror	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
		_ror	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		_ror	$acc9,8,$acc9
		xor	$acc6,$t1,$t1
		_ror	$acc10,16,$acc10
		xor	$acc7,$t1,$t1
		_ror	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		_ror	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		_ror	$acc14,16,$acc14
		xor	$acc10,$t2,$t2
		_ror	$acc15,24,$acc15
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	_srm	$t0,24,$acc0
		xor	$acc14,$t3,$t3
		xor	$acc15,$t3,$t3
	_srm	$t3,16,$acc1

	_srm	$t2,8,$acc2
	ldwx,s	$acc0($tbl),$acc0
	_srm	$t1,0,$acc3
	ldwx,s	$acc1($tbl),$acc1
	_srm	$t1,24,$acc4
	ldwx,s	$acc2($tbl),$acc2
	_srm	$t0,16,$acc5
	ldwx,s	$acc3($tbl),$acc3
	_srm	$t3,8,$acc6
	ldwx,s	$acc4($tbl),$acc4
	_srm	$t2,0,$acc7
	ldwx,s	$acc5($tbl),$acc5
	_srm	$t2,24,$acc8
	ldwx,s	$acc6($tbl),$acc6
	_srm	$t1,16,$acc9
	ldwx,s	$acc7($tbl),$acc7
	_srm	$t0,8,$acc10
	ldwx,s	$acc8($tbl),$acc8
	_srm	$t3,0,$acc11
	ldwx,s	$acc9($tbl),$acc9
	_srm	$t3,24,$acc12
	ldwx,s	$acc10($tbl),$acc10
	_srm	$t2,16,$acc13
	ldwx,s	$acc11($tbl),$acc11
	_srm	$t1,8,$acc14
	ldwx,s	$acc12($tbl),$acc12
	_srm	$t0,0,$acc15
	ldwx,s	$acc13($tbl),$acc13
		_ror	$acc1,8,$acc1
	ldwx,s	$acc14($tbl),$acc14

		_ror	$acc2,16,$acc2
		xor	$acc0,$s0,$s0
	ldwx,s	$acc15($tbl),$acc15
		_ror	$acc3,24,$acc3
		xor	$acc1,$s0,$s0
	ldw	16($key),$t0
		_ror	$acc5,8,$acc5
		xor	$acc2,$s0,$s0
	ldw	20($key),$t1
		_ror	$acc6,16,$acc6
		xor	$acc3,$s0,$s0
	ldw	24($key),$t2
		_ror	$acc7,24,$acc7
		xor	$acc4,$s1,$s1
	ldw	28($key),$t3
		_ror	$acc9,8,$acc9
		xor	$acc5,$s1,$s1
	ldw	1024+0($tbl),%r0		; prefetch td4
		_ror	$acc10,16,$acc10
		xor	$acc6,$s1,$s1
	ldw	1024+32($tbl),%r0		; prefetch td4
		_ror	$acc11,24,$acc11
		xor	$acc7,$s1,$s1
	ldw	1024+64($tbl),%r0		; prefetch td4
		_ror	$acc13,8,$acc13
		xor	$acc8,$s2,$s2
	ldw	1024+96($tbl),%r0		; prefetch td4
		_ror	$acc14,16,$acc14
		xor	$acc9,$s2,$s2
	ldw	1024+128($tbl),%r0		; prefetch td4
		_ror	$acc15,24,$acc15
		xor	$acc10,$s2,$s2
	ldw	1024+160($tbl),%r0		; prefetch td4
	_srm	$s0,24,$acc0
		xor	$acc11,$s2,$s2
	ldw	1024+192($tbl),%r0		; prefetch td4
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$s3,$s3
	ldw	1024+224($tbl),%r0		; prefetch td4
		xor	$acc14,$s3,$s3
		xor	$acc15,$s3,$s3
	b	L\$dec_loop
	_srm	$s3,16,$acc1

	.ALIGN	16
L\$dec_last
	ldo	1024($tbl),$rounds
		_ror	$acc1,8,$acc1
		xor	$acc0,$t0,$t0
	ldw	0($key),$s0
		_ror	$acc2,16,$acc2
		xor	$acc1,$t0,$t0
	ldw	4($key),$s1
		_ror	$acc3,24,$acc3
		xor	$acc2,$t0,$t0
	ldw	8($key),$s2
		_ror	$acc5,8,$acc5
		xor	$acc3,$t0,$t0
	ldw	12($key),$s3
		_ror	$acc6,16,$acc6
		xor	$acc4,$t1,$t1
		_ror	$acc7,24,$acc7
		xor	$acc5,$t1,$t1
		_ror	$acc9,8,$acc9
		xor	$acc6,$t1,$t1
		_ror	$acc10,16,$acc10
		xor	$acc7,$t1,$t1
		_ror	$acc11,24,$acc11
		xor	$acc8,$t2,$t2
		_ror	$acc13,8,$acc13
		xor	$acc9,$t2,$t2
		_ror	$acc14,16,$acc14
		xor	$acc10,$t2,$t2
		_ror	$acc15,24,$acc15
		xor	$acc11,$t2,$t2
		xor	$acc12,$acc14,$acc14
		xor	$acc13,$t3,$t3
	_srm	$t0,24,$acc0
		xor	$acc14,$t3,$t3
		xor	$acc15,$t3,$t3
	_srm	$t3,16,$acc1

	_srm	$t2,8,$acc2
	ldbx	$acc0($rounds),$acc0
	_srm	$t1,24,$acc4
	ldbx	$acc1($rounds),$acc1
	_srm	$t0,16,$acc5
	_srm	$t1,0,$acc3
	ldbx	$acc2($rounds),$acc2
	ldbx	$acc3($rounds),$acc3
	_srm	$t3,8,$acc6
	ldbx	$acc4($rounds),$acc4
	_srm	$t2,24,$acc8
	ldbx	$acc5($rounds),$acc5
	_srm	$t1,16,$acc9
	_srm	$t2,0,$acc7
	ldbx	$acc6($rounds),$acc6
	ldbx	$acc7($rounds),$acc7
	_srm	$t0,8,$acc10
	ldbx	$acc8($rounds),$acc8
	_srm	$t3,24,$acc12
	ldbx	$acc9($rounds),$acc9
	_srm	$t2,16,$acc13
	_srm	$t3,0,$acc11
	ldbx	$acc10($rounds),$acc10
	_srm	$t1,8,$acc14
	ldbx	$acc11($rounds),$acc11
	ldbx	$acc12($rounds),$acc12
	ldbx	$acc13($rounds),$acc13
	_srm	$t0,0,$acc15
	ldbx	$acc14($rounds),$acc14

		dep	$acc0,7,8,$acc3
	ldbx	$acc15($rounds),$acc15
		dep	$acc4,7,8,$acc7
		dep	$acc1,15,8,$acc3
		dep	$acc5,15,8,$acc7
		dep	$acc2,23,8,$acc3
		dep	$acc6,23,8,$acc7
		xor	$acc3,$s0,$s0
		xor	$acc7,$s1,$s1
		dep	$acc8,7,8,$acc11
		dep	$acc12,7,8,$acc15
		dep	$acc9,15,8,$acc11
		dep	$acc13,15,8,$acc15
		dep	$acc10,23,8,$acc11
		dep	$acc14,23,8,$acc15
		xor	$acc11,$s2,$s2

	bv	(%r31)
	.EXIT
		xor	$acc15,$s3,$s3
	.PROCEND

	.ALIGN	64
L\$AES_Td
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.WORD	0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.BYTE	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.STRINGZ "AES for PA-RISC, CRYPTOGAMS by <appro\@openssl.org>"
___

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
	=~ /GNU assembler/) {
    $gnuas = 1;
}

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	# translate made up instructions: _ror, _srm
	s/_ror(\s+)(%r[0-9]+),/shd$1$2,$2,/				or

	s/_srm(\s+%r[0-9]+),([0-9]+),/
		$SIZE_T==4 ? sprintf("extru%s,%d,8,",$1,31-$2)
		:            sprintf("extrd,u%s,%d,8,",$1,63-$2)/e;

	s/(\.LEVEL\s+2\.0)W/$1w/	if ($gnuas && $SIZE_T==8);
	s/\.SPACE\s+\$TEXT\$/.text/	if ($gnuas && $SIZE_T==8);
	s/\.SUBSPA.*//			if ($gnuas && $SIZE_T==8);
	s/,\*/,/			if ($SIZE_T==4);
	s/\bbv\b(.*\(%r2\))/bve$1/	if ($SIZE_T==8);

	print $_,"\n";
}
close STDOUT;
