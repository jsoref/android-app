#! /usr/bin/env perl
# Copyright 2013-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


######################################################################
## Constant-time SSSE3 AES core implementation.
## version 0.1
##
## By Mike Hamburg (Stanford University), 2009
## Public domain.
##
## For details see http://shiftleft.org/papers/vector_aes/ and
## http://crypto.stanford.edu/vpaes/.

# CBC encrypt/decrypt performance in cycles per byte processed with
# 128-bit key.
#
#		aes-ppc.pl		this
# PPC74x0/G4e	35.5/52.1/(23.8)	11.9(*)/15.4
# PPC970/G5	37.9/55.0/(28.5)	22.2/28.5
# POWER6	42.7/54.3/(28.2)	63.0/92.8(**)
# POWER7	32.3/42.9/(18.4)	18.5/23.3
#
# (*)	This is ~10% worse than reported in paper. The reason is
#	twofold. This module doesn't make any assumption about
#	key schedule (or data for that matter) alignment and handles
#	it in-line. Secondly it, being transliterated from
#	vpaes-x86_64.pl, relies on "nested inversion" better suited
#	for Intel CPUs.
# (**)	Inadequate POWER6 performance is due to astronomic AltiVec
#	latency, 9 cycles per simple logical operation.

$flavour = shift;

if ($flavour =~ /64/) {
	$SIZE_T	=8;
	$LRSAVE	=2*$SIZE_T;
	$STU	="stdu";
	$POP	="ld";
	$PUSH	="std";
	$UCMP	="cmpld";
} elsif ($flavour =~ /32/) {
	$SIZE_T	=4;
	$LRSAVE	=$SIZE_T;
	$STU	="stwu";
	$POP	="lwz";
	$PUSH	="stw";
	$UCMP	="cmplw";
} else { die "nonsense $flavour"; }

$sp="r1";
$FRAME=6*$SIZE_T+13*16;	# 13*16 is for v20-v31 offload

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}ppc-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/ppc-xlate.pl" and -f $xlate) or
die "can't locate ppc-xlate.pl";

open STDOUT,"| $^X $xlate $flavour ".shift || die "can't call $xlate: $!";

$code.=<<___;
.machine	"any"

.text

.align	7	# totally strategic alignment
_vpaes_consts:
Lk_mc_forward:	# mc_forward
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
Lk_mc_backward:	# mc_backward
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
Lk_sr:		# sr
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv
	.long	0xFF, 0xFF, 0xFF, 0xFF	?inv

##
## "Hot" constants
##
Lk_inv:		# inv, inva
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_ipt:		# input transform (lo, hi)
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_sbo:		# sbou, sbot
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_sb1:		# sb1u, sb1t
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_sb2:		# sb2u, sb2t
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev

##
##  Decryption stuff
##
Lk_dipt:	# decryption input transform
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dsbo:	# decryption sbox final output
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dsb9:	# decryption sbox output *9*u, *9*t
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dsbd:	# decryption sbox output *D*u, *D*t
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dsbb:	# decryption sbox output *B*u, *B*t
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dsbe:	# decryption sbox output *E*u, *E*t
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev

##
##  Key schedule constants
##
Lk_dksd:	# decryption key schedule: invskew x*D
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dksb:	# decryption key schedule: invskew x*B
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dkse:	# decryption key schedule: invskew x*E + 0xFF
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_dks9:	# decryption key schedule: invskew x*9
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev

Lk_rcon:	# rcon
	.long	0xFF, 0xFF, 0xFF, 0xFF	?asis
Lk_s63:
	.long	0xFF, 0xFF, 0xFF, 0xFF	?asis

Lk_opt:		# output transform
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
Lk_deskew:	# deskew tables: inverts the sbox's "skew"
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
	.long	0xFF, 0xFF, 0xFF, 0xFF	?rev
.align	5
Lconsts:
	mflr	r0
	bcl	20,31,\$+4
	mflr	r12	#vvvvv "distance between . and _vpaes_consts
	addi	r12,r12,-0xFF
	mtlr	r0
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0
.asciz  "Vector Permutation AES for AltiVec, Mike Hamburg (Stanford University)"
.align	6
___

my ($inptail,$inpperm,$outhead,$outperm,$outmask,$keyperm) = map("v$_",(26..31));
{
my ($inp,$out,$key) = map("r$_",(3..5));

my ($invlo,$invhi,$iptlo,$ipthi,$sbou,$sbot) = map("v$_",(10..15));
my ($sb1u,$sb1t,$sb2u,$sb2t) = map("v$_",(16..19));
my ($sb9u,$sb9t,$sbdu,$sbdt,$sbbu,$sbbt,$sbeu,$sbet)=map("v$_",(16..23));

$code.=<<___;
##
##  _aes_preheat
##
##  Fills register %r10 -> .aes_consts (so you can -fPIC)
##  and %xmm9-%xmm15 as specified below.
##
.align	4
_vpaes_encrypt_preheat:
	mflr	r8
	bl	Lconsts
	mtlr	r8
	li	r11, 0xFF		# Lk_inv
	li	r10, 0xFF
	li	r9,  0xFF		# Lk_ipt
	li	r8,  0xFF
	vxor	v7, v7, v7		# 0xFF..00
	vspltisb	v8,4		# 0xFF..04
	vspltisb	v9,0xFF		# 0xFF..0f
	lvx	$invlo, r12, r11
	li	r11, 0xFF
	lvx	$invhi, r12, r10
	li	r10, 0xFF
	lvx	$iptlo, r12, r9
	li	r9,  0xFF
	lvx	$ipthi, r12, r8
	li	r8,  0xFF
	lvx	$sbou, r12, r11
	li	r11, 0xFF
	lvx	$sbot, r12, r10
	li	r10, 0xFF
	lvx	$sb1u, r12, r9
	lvx	$sb1t, r12, r8
	lvx	$sb2u, r12, r11
	lvx	$sb2t, r12, r10
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

##
##  _aes_encrypt_core
##
##  AES-encrypt %xmm0.
##
##  Inputs:
##     %xmm0 = input
##     %xmm9-%xmm15 as in _vpaes_preheat
##    (%rdx) = scheduled keys
##
##  Output in %xmm0
##  Clobbers  %xmm1-%xmm6, %r9, %r10, %r11, %rax
##
##
.align 5
_vpaes_encrypt_core:
	lwz	r8, 240($key)		# pull rounds
	li	r9, 16
	lvx	v5, 0, $key		# vmovdqu	(%r9),	%xmm5		# round0 key
	li	r11, 0xFF
	lvx	v6, r9, $key
	addi	r9, r9, 16
	?vperm	v5, v5, v6, $keyperm	# align round key
	addi	r10, r11, 0xFF
	vsrb	v1, v0, v8		# vpsrlb	\$4,	%xmm0,	%xmm0
	vperm	v0, $iptlo, $iptlo, v0	# vpshufb	%xmm1,	%xmm2,	%xmm1
	vperm	v1, $ipthi, $ipthi, v1	# vpshufb	%xmm0,	%xmm3,	%xmm2
	vxor	v0, v0, v5		# vpxor	%xmm5,	%xmm1,	%xmm0
	vxor	v0, v0, v1		# vpxor	%xmm2,	%xmm0,	%xmm0
	mtctr	r8
	b	Lenc_entry

.align 4
Lenc_loop:
	# middle of middle round
	vperm	v4, $sb1t, v7, v2	# vpshufb	%xmm2,	%xmm13,	%xmm4	# 4 = sb1u
	lvx	v1, r12, r11		# vmovdqa	-0xFF(%r11,%r10), %xmm1	# .Lk_mc_forward[]
	addi	r11, r11, 16
	vperm	v0, $sb1u, v7, v3	# vpshufb	%xmm3,	%xmm12,	%xmm0	# 0 = sb1t
	vxor	v4, v4, v5		# vpxor		%xmm5,	%xmm4,	%xmm4	# 4 = sb1u + k
	andi.	r11, r11, 0xFF		# and		\$0xFF, %r11	# ... mod 4
	vperm	v5, $sb2t, v7, v2	# vpshufb	%xmm2,	%xmm15,	%xmm5	# 4 = sb2u
	vxor	v0, v0, v4		# vpxor		%xmm4,	%xmm0,	%xmm0	# 0 = A
	vperm	v2, $sb2u, v7, v3	# vpshufb	%xmm3,	%xmm14,	%xmm2	# 2 = sb2t
	lvx	v4, r12, r10		# vmovdqa	(%r11,%r10), %xmm4	# .Lk_mc_backward[]
	addi	r10, r11, 0xFF
	vperm	v3, v0, v7, v1		# vpshufb	%xmm1,	%xmm0,	%xmm3	# 0 = B
	vxor	v2, v2, v5		# vpxor		%xmm5,	%xmm2,	%xmm2	# 2 = 2A
	vperm	v0, v0, v7, v4		# vpshufb	%xmm4,	%xmm0,	%xmm0	# 3 = D
	vxor	v3, v3, v2		# vpxor		%xmm2,	%xmm3,	%xmm3	# 0 = 2A+B
	vperm	v4, v3, v7, v1		# vpshufb	%xmm1,	%xmm3,	%xmm4	# 0 = 2B+C
	vxor	v0, v0, v3		# vpxor		%xmm3,	%xmm0,	%xmm0	# 3 = 2A+B+D
	vxor	v0, v0, v4		# vpxor		%xmm4,	%xmm0, %xmm0	# 0 = 2A+3B+C+D

Lenc_entry:
	# top of round
	vsrb	v1, v0, v8		# vpsrlb	\$4,	%xmm0,	%xmm0	# 1 = i
	vperm	v5, $invhi, $invhi, v0	# vpshufb	%xmm1,	%xmm11,	%xmm5	# 2 = a/k
	vxor	v0, v0, v1		# vpxor		%xmm0,	%xmm1,	%xmm1	# 0 = j
	vperm	v3, $invlo, $invlo, v1	# vpshufb	%xmm0, 	%xmm10,	%xmm3  	# 3 = 1/i
	vperm	v4, $invlo, $invlo, v0	# vpshufb	%xmm1, 	%xmm10,	%xmm4  	# 4 = 1/j
	vand	v0, v0, v9
	vxor	v3, v3, v5		# vpxor		%xmm5,	%xmm3,	%xmm3	# 3 = iak = 1/i + a/k
	vxor	v4, v4, v5		# vpxor		%xmm5,	%xmm4,	%xmm4  	# 4 = jak = 1/j + a/k
	vperm	v2, $invlo, v7, v3	# vpshufb	%xmm3,	%xmm10,	%xmm2  	# 2 = 1/iak
	vmr	v5, v6
	lvx	v6, r9, $key		# vmovdqu	(%r9), %xmm5
	vperm	v3, $invlo, v7, v4	# vpshufb	%xmm4,	%xmm10,	%xmm3	# 3 = 1/jak
	addi	r9, r9, 16
	vxor	v2, v2, v0		# vpxor		%xmm1,	%xmm2,	%xmm2  	# 2 = io
	?vperm	v5, v5, v6, $keyperm	# align round key
	vxor	v3, v3, v1		# vpxor		%xmm0,	%xmm3,	%xmm3	# 3 = jo
	bdnz	Lenc_loop

	# middle of last round
	addi	r10, r11, 0xFF
					# vmovdqa	-0xFF(%r10), %xmm4	# 3 : sbou	.Lk_sbo
					# vmovdqa	-0xFF(%r10), %xmm0	# 0 : sbot	.Lk_sbo+16
	vperm	v4, $sbou, v7, v2	# vpshufb	%xmm2,	%xmm4,	%xmm4	# 4 = sbou
	lvx	v1, r12, r10		# vmovdqa	0xFF(%r11,%r10), %xmm1	# .Lk_sr[]
	vperm	v0, $sbot, v7, v3	# vpshufb	%xmm3,	%xmm0,	%xmm0	# 0 = sb1t
	vxor	v4, v4, v5		# vpxor		%xmm5,	%xmm4,	%xmm4	# 4 = sb1u + k
	vxor	v0, v0, v4		# vpxor		%xmm4,	%xmm0,	%xmm0	# 0 = A
	vperm	v0, v0, v7, v1		# vpshufb	%xmm1,	%xmm0,	%xmm0
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

.globl	.vpaes_encrypt
.align	5
.vpaes_encrypt:
	$STU	$sp,-$FRAME($sp)
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mflr	r6
	mfspr	r7, 256			# save vrsave
	stvx	v20,r10,$sp
	addi	r10,r10,32
	stvx	v21,r11,$sp
	addi	r11,r11,32
	stvx	v22,r10,$sp
	addi	r10,r10,32
	stvx	v23,r11,$sp
	addi	r11,r11,32
	stvx	v24,r10,$sp
	addi	r10,r10,32
	stvx	v25,r11,$sp
	addi	r11,r11,32
	stvx	v26,r10,$sp
	addi	r10,r10,32
	stvx	v27,r11,$sp
	addi	r11,r11,32
	stvx	v28,r10,$sp
	addi	r10,r10,32
	stvx	v29,r11,$sp
	addi	r11,r11,32
	stvx	v30,r10,$sp
	stvx	v31,r11,$sp
	stw	r7,`$FRAME-4`($sp)	# save vrsave
	li	r0, -1
	$PUSH	r6,`$FRAME+$LRSAVE`($sp)
	mtspr	256, r0			# preserve all AltiVec registers

	bl	_vpaes_encrypt_preheat

	?lvsl	$inpperm, 0, $inp	# prepare for unaligned access
	lvx	v0, 0, $inp
	addi	$inp, $inp, 15		# 15 is not a typo
	 ?lvsr	$outperm, 0, $out
	?lvsl	$keyperm, 0, $key	# prepare for unaligned access
	lvx	$inptail, 0, $inp	# redundant in aligned case
	?vperm	v0, v0, $inptail, $inpperm

	bl	_vpaes_encrypt_core

	andi.	r8, $out, 15
	li	r9, 16
	beq	Lenc_out_aligned

	vperm	v0, v0, v0, $outperm	# rotate right/left
	mtctr	r9
Lenc_out_unaligned:
	stvebx	v0, 0, $out
	addi	$out, $out, 1
	bdnz	Lenc_out_unaligned
	b	Lenc_done

.align	4
Lenc_out_aligned:
	stvx	v0, 0, $out
Lenc_done:

	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mtlr	r6
	mtspr	256, r7			# restore vrsave
	lvx	v20,r10,$sp
	addi	r10,r10,32
	lvx	v21,r11,$sp
	addi	r11,r11,32
	lvx	v22,r10,$sp
	addi	r10,r10,32
	lvx	v23,r11,$sp
	addi	r11,r11,32
	lvx	v24,r10,$sp
	addi	r10,r10,32
	lvx	v25,r11,$sp
	addi	r11,r11,32
	lvx	v26,r10,$sp
	addi	r10,r10,32
	lvx	v27,r11,$sp
	addi	r11,r11,32
	lvx	v28,r10,$sp
	addi	r10,r10,32
	lvx	v29,r11,$sp
	addi	r11,r11,32
	lvx	v30,r10,$sp
	lvx	v31,r11,$sp
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,0xFF,1,0xFF,0,3,0
	.long	0
.size	.vpaes_encrypt,.-.vpaes_encrypt

.align	4
_vpaes_decrypt_preheat:
	mflr	r8
	bl	Lconsts
	mtlr	r8
	li	r11, 0xFF		# Lk_inv
	li	r10, 0xFF
	li	r9,  0xFF		# Ldipt
	li	r8,  0xFF
	vxor	v7, v7, v7		# 0xFF..00
	vspltisb	v8,4		# 0xFF..04
	vspltisb	v9,0xFF		# 0xFF..0f
	lvx	$invlo, r12, r11
	li	r11, 0xFF
	lvx	$invhi, r12, r10
	li	r10, 0xFF
	lvx	$iptlo, r12, r9
	li	r9,  0xFF
	lvx	$ipthi, r12, r8
	li	r8,  0xFF
	lvx	$sbou, r12, r11
	li	r11, 0xFF
	lvx	$sbot, r12, r10
	li	r10, 0xFF
	lvx	$sb9u, r12, r9
	li	r9,  0xFF
	lvx	$sb9t, r12, r8
	li	r8,  0xFF
	lvx	$sbdu, r12, r11
	li	r11, 0xFF
	lvx	$sbdt, r12, r10
	li	r10, 0xFF
	lvx	$sbbu, r12, r9
	lvx	$sbbt, r12, r8
	lvx	$sbeu, r12, r11
	lvx	$sbet, r12, r10
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

##
##  Decryption core
##
##  Same API as encryption core.
##
.align	4
_vpaes_decrypt_core:
	lwz	r8, 240($key)		# pull rounds
	li	r9, 16
	lvx	v5, 0, $key		# vmovdqu	(%r9),	%xmm4		# round0 key
	li	r11, 0xFF
	lvx	v6, r9, $key
	addi	r9, r9, 16
	?vperm	v5, v5, v6, $keyperm	# align round key
	vsrb	v1, v0, v8		# vpsrlb	\$4,	%xmm0,	%xmm0
	vperm	v0, $iptlo, $iptlo, v0	# vpshufb	%xmm1,	%xmm2,	%xmm2
	vperm	v1, $ipthi, $ipthi, v1	# vpshufb	%xmm0,	%xmm1,	%xmm0
	vxor	v0, v0, v5		# vpxor	%xmm4,	%xmm2,	%xmm2
	vxor	v0, v0, v1		# vpxor	%xmm2,	%xmm0,	%xmm0
	mtctr	r8
	b	Ldec_entry

.align 4
Ldec_loop:
#
#  Inverse mix columns
#
	lvx	v0, r12, r11		# v5 and v0 are flipped
					# vmovdqa	-0xFF(%r10),%xmm4		# 4 : sb9u
					# vmovdqa	-0xFF(%r10),%xmm1		# 0 : sb9t
	vperm	v4, $sb9u, v7, v2	# vpshufb	%xmm2,	%xmm4,	%xmm4		# 4 = sb9u
	subi	r11, r11, 16
	vperm	v1, $sb9t, v7, v3	# vpshufb	%xmm3,	%xmm1,	%xmm1		# 0 = sb9t
	andi.	r11, r11, 0xFF
	vxor	v5, v5, v4		# vpxor		%xmm4,	%xmm0,	%xmm0
					# vmovdqa	0xFF(%r10),%xmm4		# 4 : sbdu
	vxor	v5, v5, v1		# vpxor		%xmm1,	%xmm0,	%xmm0		# 0 = ch
					# vmovdqa	0xFF(%r10),%xmm1		# 0 : sbdt

	vperm	v4, $sbdu, v7, v2	# vpshufb	%xmm2,	%xmm4,	%xmm4		# 4 = sbdu
	vperm 	v5, v5, v7, v0		# vpshufb	%xmm5,	%xmm0,	%xmm0		# MC ch
	vperm	v1, $sbdt, v7, v3	# vpshufb	%xmm3,	%xmm1,	%xmm1		# 0 = sbdt
	vxor	v5, v5, v4		# vpxor		%xmm4,	%xmm0,	%xmm0		# 4 = ch
					# vmovdqa	0xFF(%r10),	%xmm4		# 4 : sbbu
	vxor	v5, v5, v1		# vpxor		%xmm1,	%xmm0,	%xmm0		# 0 = ch
					# vmovdqa	0xFF(%r10),	%xmm1		# 0 : sbbt

	vperm	v4, $sbbu, v7, v2	# vpshufb	%xmm2,	%xmm4,	%xmm4		# 4 = sbbu
	vperm	v5, v5, v7, v0		# vpshufb	%xmm5,	%xmm0,	%xmm0		# MC ch
	vperm	v1, $sbbt, v7, v3	# vpshufb	%xmm3,	%xmm1,	%xmm1		# 0 = sbbt
	vxor	v5, v5, v4		# vpxor		%xmm4,	%xmm0,	%xmm0		# 4 = ch
					# vmovdqa	0xFF(%r10),	%xmm4		# 4 : sbeu
	vxor	v5, v5, v1		# vpxor		%xmm1,	%xmm0,	%xmm0		# 0 = ch
					# vmovdqa	0xFF(%r10),	%xmm1		# 0 : sbet

	vperm	v4, $sbeu, v7, v2	# vpshufb	%xmm2,	%xmm4,	%xmm4		# 4 = sbeu
	vperm	v5, v5, v7, v0		# vpshufb	%xmm5,	%xmm0,	%xmm0		# MC ch
	vperm	v1, $sbet, v7, v3	# vpshufb	%xmm3,	%xmm1,	%xmm1		# 0 = sbet
	vxor	v0, v5, v4		# vpxor		%xmm4,	%xmm0,	%xmm0		# 4 = ch
	vxor	v0, v0, v1		# vpxor		%xmm1,	%xmm0,	%xmm0		# 0 = ch

Ldec_entry:
	# top of round
	vsrb	v1, v0, v8		# vpsrlb	\$4,	%xmm0,	%xmm0	# 1 = i
	vperm	v2, $invhi, $invhi, v0	# vpshufb	%xmm1,	%xmm11,	%xmm2	# 2 = a/k
	vxor	v0, v0, v1		# vpxor		%xmm0,	%xmm1,	%xmm1	# 0 = j
	vperm	v3, $invlo, $invlo, v1	# vpshufb	%xmm0, 	%xmm10,	%xmm3	# 3 = 1/i
	vperm	v4, $invlo, $invlo, v0	# vpshufb	%xmm1,	%xmm10,	%xmm4	# 4 = 1/j
	vand	v0, v0, v9
	vxor	v3, v3, v2		# vpxor		%xmm2,	%xmm3,	%xmm3	# 3 = iak = 1/i + a/k
	vxor	v4, v4, v2		# vpxor		%xmm2, 	%xmm4,	%xmm4	# 4 = jak = 1/j + a/k
	vperm	v2, $invlo, v7, v3	# vpshufb	%xmm3,	%xmm10,	%xmm2	# 2 = 1/iak
	vmr	v5, v6
	lvx	v6, r9, $key		# vmovdqu	(%r9),	%xmm0
	vperm	v3, $invlo, v7, v4	# vpshufb	%xmm4,  %xmm10,	%xmm3	# 3 = 1/jak
	addi	r9, r9, 16
	vxor	v2, v2, v0		# vpxor		%xmm1,	%xmm2,	%xmm2	# 2 = io
	?vperm	v5, v5, v6, $keyperm	# align round key
	vxor	v3, v3, v1		# vpxor		%xmm0,  %xmm3,	%xmm3	# 3 = jo
	bdnz	Ldec_loop

	# middle of last round
	addi	r10, r11, 0xFF
					# vmovdqa	0xFF(%r10),	%xmm4	# 3 : sbou
	vperm	v4, $sbou, v7, v2	# vpshufb	%xmm2,	%xmm4,	%xmm4	# 4 = sbou
					# vmovdqa	0xFF(%r10),	%xmm1	# 0 : sbot
	lvx	v2, r12, r10		# vmovdqa	-0xFF(%r11),	%xmm2	# .Lk_sr-.Lk_dsbd=-0xFF
	vperm	v1, $sbot, v7, v3	# vpshufb	%xmm3,	%xmm1,	%xmm1	# 0 = sb1t
	vxor	v4, v4, v5		# vpxor		%xmm0,	%xmm4,	%xmm4	# 4 = sb1u + k
	vxor	v0, v1, v4		# vpxor		%xmm4,	%xmm1,	%xmm0	# 0 = A
	vperm	v0, v0, v7, v2		# vpshufb	%xmm2,	%xmm0,	%xmm0
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

.globl	.vpaes_decrypt
.align	5
.vpaes_decrypt:
	$STU	$sp,-$FRAME($sp)
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mflr	r6
	mfspr	r7, 256			# save vrsave
	stvx	v20,r10,$sp
	addi	r10,r10,32
	stvx	v21,r11,$sp
	addi	r11,r11,32
	stvx	v22,r10,$sp
	addi	r10,r10,32
	stvx	v23,r11,$sp
	addi	r11,r11,32
	stvx	v24,r10,$sp
	addi	r10,r10,32
	stvx	v25,r11,$sp
	addi	r11,r11,32
	stvx	v26,r10,$sp
	addi	r10,r10,32
	stvx	v27,r11,$sp
	addi	r11,r11,32
	stvx	v28,r10,$sp
	addi	r10,r10,32
	stvx	v29,r11,$sp
	addi	r11,r11,32
	stvx	v30,r10,$sp
	stvx	v31,r11,$sp
	stw	r7,`$FRAME-4`($sp)	# save vrsave
	li	r0, -1
	$PUSH	r6,`$FRAME+$LRSAVE`($sp)
	mtspr	256, r0			# preserve all AltiVec registers

	bl	_vpaes_decrypt_preheat

	?lvsl	$inpperm, 0, $inp	# prepare for unaligned access
	lvx	v0, 0, $inp
	addi	$inp, $inp, 15		# 15 is not a typo
	 ?lvsr	$outperm, 0, $out
	?lvsl	$keyperm, 0, $key
	lvx	$inptail, 0, $inp	# redundant in aligned case
	?vperm	v0, v0, $inptail, $inpperm

	bl	_vpaes_decrypt_core

	andi.	r8, $out, 15
	li	r9, 16
	beq	Ldec_out_aligned

	vperm	v0, v0, v0, $outperm	# rotate right/left
	mtctr	r9
Ldec_out_unaligned:
	stvebx	v0, 0, $out
	addi	$out, $out, 1
	bdnz	Ldec_out_unaligned
	b	Ldec_done

.align	4
Ldec_out_aligned:
	stvx	v0, 0, $out
Ldec_done:

	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mtlr	r6
	mtspr	256, r7			# restore vrsave
	lvx	v20,r10,$sp
	addi	r10,r10,32
	lvx	v21,r11,$sp
	addi	r11,r11,32
	lvx	v22,r10,$sp
	addi	r10,r10,32
	lvx	v23,r11,$sp
	addi	r11,r11,32
	lvx	v24,r10,$sp
	addi	r10,r10,32
	lvx	v25,r11,$sp
	addi	r11,r11,32
	lvx	v26,r10,$sp
	addi	r10,r10,32
	lvx	v27,r11,$sp
	addi	r11,r11,32
	lvx	v28,r10,$sp
	addi	r10,r10,32
	lvx	v29,r11,$sp
	addi	r11,r11,32
	lvx	v30,r10,$sp
	lvx	v31,r11,$sp
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,0xFF,1,0xFF,0,3,0
	.long	0
.size	.vpaes_decrypt,.-.vpaes_decrypt

.globl	.vpaes_cbc_encrypt
.align	5
.vpaes_cbc_encrypt:
	${UCMP}i r5,16
	bltlr-

	$STU	$sp,-`($FRAME+2*$SIZE_T)`($sp)
	mflr	r0
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mfspr	r12, 256
	stvx	v20,r10,$sp
	addi	r10,r10,32
	stvx	v21,r11,$sp
	addi	r11,r11,32
	stvx	v22,r10,$sp
	addi	r10,r10,32
	stvx	v23,r11,$sp
	addi	r11,r11,32
	stvx	v24,r10,$sp
	addi	r10,r10,32
	stvx	v25,r11,$sp
	addi	r11,r11,32
	stvx	v26,r10,$sp
	addi	r10,r10,32
	stvx	v27,r11,$sp
	addi	r11,r11,32
	stvx	v28,r10,$sp
	addi	r10,r10,32
	stvx	v29,r11,$sp
	addi	r11,r11,32
	stvx	v30,r10,$sp
	stvx	v31,r11,$sp
	stw	r12,`$FRAME-4`($sp)	# save vrsave
	$PUSH	r30,`$FRAME+$SIZE_T*0`($sp)
	$PUSH	r31,`$FRAME+$SIZE_T*1`($sp)
	li	r9, -16
	$PUSH	r0, `$FRAME+$SIZE_T*2+$LRSAVE`($sp)

	and	r30, r5, r9		# copy length&-16
	andi.	r9, $out, 15		# is $out aligned?
	mr	r5, r6			# copy pointer to key
	mr	r31, r7			# copy pointer to iv
	li	r6, -1
	mcrf	cr1, cr0		# put aside $out alignment flag
	mr	r7, r12			# copy vrsave
	mtspr	256, r6			# preserve all AltiVec registers

	lvx	v24, 0, r31		# load [potentially unaligned] iv
	li	r9, 15
	?lvsl	$inpperm, 0, r31
	lvx	v25, r9, r31
	?vperm	v24, v24, v25, $inpperm

	cmpwi	r8, 0			# test direction
	neg	r8, $inp		# prepare for unaligned access
	 vxor	v7, v7, v7
	?lvsl	$keyperm, 0, $key
	 ?lvsr	$outperm, 0, $out
	?lvsr	$inpperm, 0, r8		# -$inp
	 vnor	$outmask, v7, v7	# 0xFF..ff
	lvx	$inptail, 0, $inp
	 ?vperm	$outmask, v7, $outmask, $outperm
	addi	$inp, $inp, 15		# 15 is not a typo

	beq	Lcbc_decrypt

	bl	_vpaes_encrypt_preheat
	li	r0, 16

	beq	cr1, Lcbc_enc_loop	# $out is aligned

	vmr	v0, $inptail
	lvx	$inptail, 0, $inp
	addi	$inp, $inp, 16
	?vperm	v0, v0, $inptail, $inpperm
	vxor	v0, v0, v24		# ^= iv

	bl	_vpaes_encrypt_core

	andi.	r8, $out, 15
	vmr	v24, v0			# put aside iv
	sub	r9, $out, r8
	vperm	$outhead, v0, v0, $outperm	# rotate right/left

Lcbc_enc_head:
	stvebx	$outhead, r8, r9
	cmpwi	r8, 15
	addi	r8, r8, 1
	bne	Lcbc_enc_head

	sub.	r30, r30, r0		# len -= 16
	addi	$out, $out, 16
	beq	Lcbc_unaligned_done

Lcbc_enc_loop:
	vmr	v0, $inptail
	lvx	$inptail, 0, $inp
	addi	$inp, $inp, 16
	?vperm	v0, v0, $inptail, $inpperm
	vxor	v0, v0, v24		# ^= iv

	bl	_vpaes_encrypt_core

	vmr	v24, v0			# put aside iv
	sub.	r30, r30, r0		# len -= 16
	vperm	v0, v0, v0, $outperm	# rotate right/left
	vsel	v1, $outhead, v0, $outmask
	vmr	$outhead, v0
	stvx	v1, 0, $out
	addi	$out, $out, 16
	bne	Lcbc_enc_loop

	b	Lcbc_done

.align	5
Lcbc_decrypt:
	bl	_vpaes_decrypt_preheat
	li	r0, 16

	beq	cr1, Lcbc_dec_loop	# $out is aligned

	vmr	v0, $inptail
	lvx	$inptail, 0, $inp
	addi	$inp, $inp, 16
	?vperm	v0, v0, $inptail, $inpperm
	vmr	v25, v0			# put aside input

	bl	_vpaes_decrypt_core

	andi.	r8, $out, 15
	vxor	v0, v0, v24		# ^= iv
	vmr	v24, v25
	sub	r9, $out, r8
	vperm	$outhead, v0, v0, $outperm	# rotate right/left

Lcbc_dec_head:
	stvebx	$outhead, r8, r9
	cmpwi	r8, 15
	addi	r8, r8, 1
	bne	Lcbc_dec_head

	sub.	r30, r30, r0		# len -= 16
	addi	$out, $out, 16
	beq	Lcbc_unaligned_done

Lcbc_dec_loop:
	vmr	v0, $inptail
	lvx	$inptail, 0, $inp
	addi	$inp, $inp, 16
	?vperm	v0, v0, $inptail, $inpperm
	vmr	v25, v0			# put aside input

	bl	_vpaes_decrypt_core

	vxor	v0, v0, v24		# ^= iv
	vmr	v24, v25
	sub.	r30, r30, r0		# len -= 16
	vperm	v0, v0, v0, $outperm	# rotate right/left
	vsel	v1, $outhead, v0, $outmask
	vmr	$outhead, v0
	stvx	v1, 0, $out
	addi	$out, $out, 16
	bne	Lcbc_dec_loop

Lcbc_done:
	beq	cr1, Lcbc_write_iv	# $out is aligned

Lcbc_unaligned_done:
	andi.	r8, $out, 15
	sub	$out, $out, r8
	li	r9, 0
Lcbc_tail:
	stvebx	$outhead, r9, $out
	addi	r9, r9, 1
	cmpw	r9, r8
	bne	Lcbc_tail

Lcbc_write_iv:
	neg	r8, r31			# write [potentially unaligned] iv
	li	r10, 4
	?lvsl	$outperm, 0, r8
	li	r11, 8
	li	r12, 12
	vperm	v24, v24, v24, $outperm	# rotate right/left
	stvewx	v24, 0, r31		# ivp is at least 32-bit aligned
	stvewx	v24, r10, r31
	stvewx	v24, r11, r31
	stvewx	v24, r12, r31

	mtspr	256, r7			# restore vrsave
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	lvx	v20,r10,$sp
	addi	r10,r10,32
	lvx	v21,r11,$sp
	addi	r11,r11,32
	lvx	v22,r10,$sp
	addi	r10,r10,32
	lvx	v23,r11,$sp
	addi	r11,r11,32
	lvx	v24,r10,$sp
	addi	r10,r10,32
	lvx	v25,r11,$sp
	addi	r11,r11,32
	lvx	v26,r10,$sp
	addi	r10,r10,32
	lvx	v27,r11,$sp
	addi	r11,r11,32
	lvx	v28,r10,$sp
	addi	r10,r10,32
	lvx	v29,r11,$sp
	addi	r11,r11,32
	lvx	v30,r10,$sp
	lvx	v31,r11,$sp
Lcbc_abort:
	$POP	r0, `$FRAME+$SIZE_T*2+$LRSAVE`($sp)
	$POP	r30,`$FRAME+$SIZE_T*0`($sp)
	$POP	r31,`$FRAME+$SIZE_T*1`($sp)
	mtlr	r0
	addi	$sp,$sp,`$FRAME+$SIZE_T*2`
	blr
	.long	0
	.byte	0,12,0xFF,1,0xFF,2,6,0
	.long	0
.size	.vpaes_cbc_encrypt,.-.vpaes_cbc_encrypt
___
}
{
my ($inp,$bits,$out)=map("r$_",(3..5));
my $dir="cr1";
my ($invlo,$invhi,$iptlo,$ipthi,$rcon) = map("v$_",(10..13,24));

$code.=<<___;
########################################################
##                                                    ##
##                  AES key schedule                  ##
##                                                    ##
########################################################
.align	4
_vpaes_key_preheat:
	mflr	r8
	bl	Lconsts
	mtlr	r8
	li	r11, 0xFF		# Lk_inv
	li	r10, 0xFF
	li	r9,  0xFF		# L_ipt
	li	r8,  0xFF

	vspltisb	v8,4		# 0xFF..04
	vxor	v9,v9,v9		# 0xFF..00
	lvx	$invlo, r12, r11	# Lk_inv
	li	r11, 0xFF
	lvx	$invhi, r12, r10
	li	r10, 0xFF
	lvx	$iptlo, r12, r9		# Lk_ipt
	li	r9, 0xFF
	lvx	$ipthi, r12, r8
	li	r8, 0xFF

	lvx	v14, r12, r11		# Lk_sb1
	li	r11, 0xFF
	lvx	v15, r12, r10
	li	r10, 0xFF

	lvx	v16, r12, r9		# Lk_dksd
	li	r9, 0xFF
	lvx	v17, r12, r8
	li	r8, 0xFF
	lvx	v18, r12, r11		# Lk_dksb
	li	r11, 0xFF
	lvx	v19, r12, r10
	li	r10, 0xFF
	lvx	v20, r12, r9		# Lk_dkse
	li	r9, 0xFF
	lvx	v21, r12, r8
	li	r8, 0xFF
	lvx	v22, r12, r11		# Lk_dks9
	lvx	v23, r12, r10

	lvx	v24, r12, r9		# Lk_rcon
	lvx	v25, 0, r12		# Lk_mc_forward[0]
	lvx	v26, r12, r8		# Lks63
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

.align	4
_vpaes_schedule_core:
	mflr	r7

	bl	_vpaes_key_preheat	# load the tables

	#lvx	v0, 0, $inp		# vmovdqu	(%rdi),	%xmm0		# load key (unaligned)
	neg	r8, $inp		# prepare for unaligned access
	lvx	v0, 0, $inp
	addi	$inp, $inp, 15		# 15 is not typo
	?lvsr	$inpperm, 0, r8		# -$inp
	lvx	v6, 0, $inp		# v6 serves as inptail
	addi	$inp, $inp, 8
	?vperm	v0, v0, v6, $inpperm

	# input transform
	vmr	v3, v0			# vmovdqa	%xmm0,	%xmm3
	bl	_vpaes_schedule_transform
	vmr	v7, v0			# vmovdqa	%xmm0,	%xmm7

	bne	$dir, Lschedule_am_decrypting

	# encrypting, output zeroth round key after transform
	li	r8, 0xFF		# mov	\$0xFF,%r8d
	li	r9, 4
	li	r10, 8
	li	r11, 12

	?lvsr	$outperm, 0, $out	# prepare for unaligned access
	vnor	$outmask, v9, v9	# 0xFF..ff
	?vperm	$outmask, v9, $outmask, $outperm

	#stvx	v0, 0, $out		# vmovdqu	%xmm0,	(%rdx)
	vperm	$outhead, v0, v0, $outperm	# rotate right/left
	stvewx	$outhead, 0, $out	# some are superfluous
	stvewx	$outhead, r9, $out
	stvewx	$outhead, r10, $out
	addi	r10, r12, 0xFF		# lea	.Lk_sr(%rip),%r10
	stvewx	$outhead, r11, $out
	b	Lschedule_go

Lschedule_am_decrypting:
	srwi	r8, $bits, 1		# shr	\$1,%r8d
	andi.	r8, r8, 32		# and	\$32,%r8d
	xori	r8, r8, 32		# xor	\$32,%r8d	# nbits==192?0:32
	addi	r10, r12, 0xFF		# lea	.Lk_sr(%rip),%r10
	# decrypting, output zeroth round key after shiftrows
	lvx	v1, r8, r10		# vmovdqa	(%r8,%r10),	%xmm1
	li	r9, 4
	li	r10, 8
	li	r11, 12
	vperm	v4, v3, v3, v1		# vpshufb	%xmm1,	%xmm3,	%xmm3

	neg	r0, $out		# prepare for unaligned access
	?lvsl	$outperm, 0, r0
	vnor	$outmask, v9, v9	# 0xFF..ff
	?vperm	$outmask, $outmask, v9, $outperm

	#stvx	v4, 0, $out		# vmovdqu	%xmm3,	(%rdx)
	vperm	$outhead, v4, v4, $outperm	# rotate right/left
	stvewx	$outhead, 0, $out	# some are superfluous
	stvewx	$outhead, r9, $out
	stvewx	$outhead, r10, $out
	addi	r10, r12, 0xFF		# lea	.Lk_sr(%rip),%r10
	stvewx	$outhead, r11, $out
	addi	$out, $out, 15		# 15 is not typo
	xori	r8, r8, 0xFF		# xor	\$0xFF, %r8

Lschedule_go:
	cmplwi	$bits, 192		# cmp	\$192,	%esi
	bgt	Lschedule_256
	beq	Lschedule_192
	# 128: fall though

##
##  .schedule_128
##
##  128-bit specific part of key schedule.
##
##  This schedule is really simple, because all its parts
##  are accomplished by the subroutines.
##
Lschedule_128:
	li	r0, 10			# mov	\$10, %esi
	mtctr	r0

Loop_schedule_128:
	bl 	_vpaes_schedule_round
	bdz 	Lschedule_mangle_last	# dec	%esi
	bl	_vpaes_schedule_mangle	# write output
	b 	Loop_schedule_128

##
##  .aes_schedule_192
##
##  192-bit specific part of key schedule.
##
##  The main body of this schedule is the same as the 128-bit
##  schedule, but with more smearing.  The long, high side is
##  stored in %xmm7 as before, and the short, low side is in
##  the high bits of %xmm6.
##
##  This schedule is somewhat nastier, however, because each
##  round produces 192 bits of key material, or 1.5 round keys.
##  Therefore, on each cycle we do 2 rounds and produce 3 round
##  keys.
##
.align	4
Lschedule_192:
	li	r0, 4			# mov	\$4,	%esi
	lvx	v0, 0, $inp
	?vperm	v0, v6, v0, $inpperm
	?vsldoi	v0, v3, v0, 8		# vmovdqu	8(%rdi),%xmm0		# load key part 2 (very unaligned)
	bl	_vpaes_schedule_transform	# input transform
	?vsldoi	v6, v0, v9, 8
	?vsldoi	v6, v9, v6, 8		# clobber "low" side with zeros
	mtctr	r0

Loop_schedule_192:
	bl	_vpaes_schedule_round
	?vsldoi	v0, v6, v0, 8		# vpalignr	\$8,%xmm6,%xmm0,%xmm0
	bl	_vpaes_schedule_mangle	# save key n
	bl	_vpaes_schedule_192_smear
	bl	_vpaes_schedule_mangle	# save key n+1
	bl	_vpaes_schedule_round
	bdz 	Lschedule_mangle_last	# dec	%esi
	bl	_vpaes_schedule_mangle	# save key n+2
	bl	_vpaes_schedule_192_smear
	b	Loop_schedule_192

##
##  .aes_schedule_256
##
##  256-bit specific part of key schedule.
##
##  The structure here is very similar to the 128-bit
##  schedule, but with an additional "low side" in
##  %xmm6.  The low side's rounds are the same as the
##  high side's, except no rcon and no rotation.
##
.align	4
Lschedule_256:
	li	r0, 7			# mov	\$7, %esi
	addi	$inp, $inp, 8
	lvx	v0, 0, $inp		# vmovdqu	16(%rdi),%xmm0		# load key part 2 (unaligned)
	?vperm	v0, v6, v0, $inpperm
	bl	_vpaes_schedule_transform	# input transform
	mtctr	r0

Loop_schedule_256:
	bl	_vpaes_schedule_mangle	# output low result
	vmr	v6, v0			# vmovdqa	%xmm0,	%xmm6		# save cur_lo in xmm6

	# high round
	bl	_vpaes_schedule_round
	bdz 	Lschedule_mangle_last	# dec	%esi
	bl	_vpaes_schedule_mangle

	# low round. swap xmm7 and xmm6
	?vspltw	v0, v0, 3		# vpshufd	\$0xFF,	%xmm0,	%xmm0
	vmr	v5, v7			# vmovdqa	%xmm7,	%xmm5
	vmr	v7, v6			# vmovdqa	%xmm6,	%xmm7
	bl	_vpaes_schedule_low_round
	vmr	v7, v5			# vmovdqa	%xmm5,	%xmm7

	b	Loop_schedule_256
##
##  .aes_schedule_mangle_last
##
##  Mangler for last round of key schedule
##  Mangles %xmm0
##    when encrypting, outputs out(%xmm0) ^ 63
##    when decrypting, outputs unskew(%xmm0)
##
##  Always called right before return... jumps to cleanup and exits
##
.align	4
Lschedule_mangle_last:
	# schedule last round key from xmm0
	li	r11, 0xFF		# lea	.Lk_deskew(%rip),%r11
	li	r9,  0xFF
	bne	$dir, Lschedule_mangle_last_dec

	# encrypting
	lvx	v1, r8, r10		# vmovdqa	(%r8,%r10),%xmm1
	li	r11, 0xFF		# lea		.Lk_opt(%rip),	%r11	# prepare to output transform
	li	r9,  0xFF		# prepare to output transform
	vperm	v0, v0, v0, v1		# vpshufb	%xmm1,	%xmm0,	%xmm0	# output permute

	lvx	$iptlo, r11, r12	# reload $ipt
	lvx	$ipthi, r9, r12
	addi	$out, $out, 16		# add	\$16,	%rdx
	vxor	v0, v0, v26		# vpxor		.Lk_s63(%rip),	%xmm0,	%xmm0
	bl	_vpaes_schedule_transform	# output transform

	#stvx	v0, r0, $out		# vmovdqu	%xmm0,	(%rdx)		# save last key
	vperm	v0, v0, v0, $outperm	# rotate right/left
	li	r10, 4
	vsel	v2, $outhead, v0, $outmask
	li	r11, 8
	stvx	v2, 0, $out
	li	r12, 12
	stvewx	v0, 0, $out		# some (or all) are redundant
	stvewx	v0, r10, $out
	stvewx	v0, r11, $out
	stvewx	v0, r12, $out
	b	Lschedule_mangle_done

.align	4
Lschedule_mangle_last_dec:
	lvx	$iptlo, r11, r12	# reload $ipt
	lvx	$ipthi, r9,  r12
	addi	$out, $out, -16		# add	\$-16,	%rdx
	vxor	v0, v0, v26		# vpxor	.Lk_s63(%rip),	%xmm0,	%xmm0
	bl	_vpaes_schedule_transform	# output transform

	#stvx	v0, r0, $out		# vmovdqu	%xmm0,	(%rdx)		# save last key
	addi	r9, $out, -15		# -15 is not typo
	vperm	v0, v0, v0, $outperm	# rotate right/left
	li	r10, 4
	vsel	v2, $outhead, v0, $outmask
	li	r11, 8
	stvx	v2, 0, $out
	li	r12, 12
	stvewx	v0, 0, r9		# some (or all) are redundant
	stvewx	v0, r10, r9
	stvewx	v0, r11, r9
	stvewx	v0, r12, r9


Lschedule_mangle_done:
	mtlr	r7
	# cleanup
	vxor	v0, v0, v0		# vpxor		%xmm0,	%xmm0,	%xmm0
	vxor	v1, v1, v1		# vpxor		%xmm1,	%xmm1,	%xmm1
	vxor	v2, v2, v2		# vpxor		%xmm2,	%xmm2,	%xmm2
	vxor	v3, v3, v3		# vpxor		%xmm3,	%xmm3,	%xmm3
	vxor	v4, v4, v4		# vpxor		%xmm4,	%xmm4,	%xmm4
	vxor	v5, v5, v5		# vpxor		%xmm5,	%xmm5,	%xmm5
	vxor	v6, v6, v6		# vpxor		%xmm6,	%xmm6,	%xmm6
	vxor	v7, v7, v7		# vpxor		%xmm7,	%xmm7,	%xmm7

	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

##
##  .aes_schedule_192_smear
##
##  Smear the short, low side in the 192-bit key schedule.
##
##  Inputs:
##    %xmm7: high side, b  a  x  y
##    %xmm6:  low side, d  c  0  0
##    %xmm13: 0
##
##  Outputs:
##    %xmm6: b+c+d  b+c  0  0
##    %xmm0: b+c+d  b+c  b  a
##
.align	4
_vpaes_schedule_192_smear:
	?vspltw	v0, v7, 3
	?vsldoi	v1, v9, v6, 12		# vpshufd	\$0xFF,	%xmm6,	%xmm1	# d c 0 0 -> c 0 0 0
	?vsldoi	v0, v7, v0, 8		# vpshufd	\$0xFF,	%xmm7,	%xmm0	# b a _ _ -> b b b a
	vxor	v6, v6, v1		# vpxor		%xmm1,	%xmm6,	%xmm6	# -> c+d c 0 0
	vxor	v6, v6, v0		# vpxor		%xmm0,	%xmm6,	%xmm6	# -> b+c+d b+c b a
	vmr	v0, v6
	?vsldoi	v6, v6, v9, 8
	?vsldoi	v6, v9, v6, 8		# clobber low side with zeros
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

##
##  .aes_schedule_round
##
##  Runs one main round of the key schedule on %xmm0, %xmm7
##
##  Specifically, runs subbytes on the high dword of %xmm0
##  then rotates it by one byte and xors into the low dword of
##  %xmm7.
##
##  Adds rcon from low byte of %xmm8, then rotates %xmm8 for
##  next rcon.
##
##  Smears the dwords of %xmm7 by xoring the low into the
##  second low, result into third, result into highest.
##
##  Returns results in %xmm7 = %xmm0.
##  Clobbers %xmm1-%xmm4, %r11.
##
.align	4
_vpaes_schedule_round:
	# extract rcon from xmm8
	#vxor	v4, v4, v4		# vpxor		%xmm4,	%xmm4,	%xmm4
	?vsldoi	v1, $rcon, v9, 15	# vpalignr	\$15,	%xmm8,	%xmm4,	%xmm1
	?vsldoi	$rcon, $rcon, $rcon, 15	# vpalignr	\$15,	%xmm8,	%xmm8,	%xmm8
	vxor	v7, v7, v1		# vpxor		%xmm1,	%xmm7,	%xmm7

	# rotate
	?vspltw	v0, v0, 3		# vpshufd	\$0xFF,	%xmm0,	%xmm0
	?vsldoi	v0, v0, v0, 1		# vpalignr	\$1,	%xmm0,	%xmm0,	%xmm0

	# fall through...

	# low round: same as high round, but no rotation and no rcon.
_vpaes_schedule_low_round:
	# smear xmm7
	?vsldoi	v1, v9, v7, 12		# vpslldq	\$4,	%xmm7,	%xmm1
	vxor	v7, v7, v1		# vpxor		%xmm1,	%xmm7,	%xmm7
	vspltisb	v1, 0xFF	# 0xFF..0f
	?vsldoi	v4, v9, v7, 8		# vpslldq	\$8,	%xmm7,	%xmm4

	# subbytes
	vand	v1, v1, v0		# vpand		%xmm9,	%xmm0,	%xmm1		# 0 = k
	vsrb	v0, v0, v8		# vpsrlb	\$4,	%xmm0,	%xmm0		# 1 = i
	 vxor	v7, v7, v4		# vpxor		%xmm4,	%xmm7,	%xmm7
	vperm	v2, $invhi, v9, v1	# vpshufb	%xmm1,	%xmm11,	%xmm2		# 2 = a/k
	vxor	v1, v1, v0		# vpxor		%xmm0,	%xmm1,	%xmm1		# 0 = j
	vperm	v3, $invlo, v9, v0	# vpshufb	%xmm0, 	%xmm10,	%xmm3		# 3 = 1/i
	vxor	v3, v3, v2		# vpxor		%xmm2,	%xmm3,	%xmm3		# 3 = iak = 1/i + a/k
	vperm	v4, $invlo, v9, v1	# vpshufb	%xmm1,	%xmm10,	%xmm4		# 4 = 1/j
	 vxor	v7, v7, v26		# vpxor		.Lk_s63(%rip),	%xmm7,	%xmm7
	vperm	v3, $invlo, v9, v3	# vpshufb	%xmm3,	%xmm10,	%xmm3		# 2 = 1/iak
	vxor	v4, v4, v2		# vpxor		%xmm2,	%xmm4,	%xmm4		# 4 = jak = 1/j + a/k
	vperm	v2, $invlo, v9, v4	# vpshufb	%xmm4,	%xmm10,	%xmm2		# 3 = 1/jak
	vxor	v3, v3, v1		# vpxor		%xmm1,	%xmm3,	%xmm3		# 2 = io
	vxor	v2, v2, v0		# vpxor		%xmm0,	%xmm2,	%xmm2		# 3 = jo
	vperm	v4, v15, v9, v3		# vpshufb	%xmm3,	%xmm13,	%xmm4		# 4 = sbou
	vperm	v1, v14, v9, v2		# vpshufb	%xmm2,	%xmm12,	%xmm1		# 0 = sb1t
	vxor	v1, v1, v4		# vpxor		%xmm4,	%xmm1,	%xmm1		# 0 = sbox output

	# add in smeared stuff
	vxor	v0, v1, v7		# vpxor		%xmm7,	%xmm1,	%xmm0
	vxor	v7, v1, v7		# vmovdqa	%xmm0,	%xmm7
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

##
##  .aes_schedule_transform
##
##  Linear-transform %xmm0 according to tables at (%r11)
##
##  Requires that %xmm9 = 0xFF... as in preheat
##  Output in %xmm0
##  Clobbers %xmm2
##
.align	4
_vpaes_schedule_transform:
	#vand	v1, v0, v9		# vpand		%xmm9,	%xmm0,	%xmm1
	vsrb	v2, v0, v8		# vpsrlb	\$4,	%xmm0,	%xmm0
					# vmovdqa	(%r11),	%xmm2 	# lo
	vperm	v0, $iptlo, $iptlo, v0	# vpshufb	%xmm1,	%xmm2,	%xmm2
					# vmovdqa	16(%r11),	%xmm1 # hi
	vperm	v2, $ipthi, $ipthi, v2	# vpshufb	%xmm0,	%xmm1,	%xmm0
	vxor	v0, v0, v2		# vpxor		%xmm2,	%xmm0,	%xmm0
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

##
##  .aes_schedule_mangle
##
##  Mangle xmm0 from (basis-transformed) standard version
##  to our version.
##
##  On encrypt,
##    xor with 0xFF
##    multiply by circulant 0,1,1,1
##    apply shiftrows transform
##
##  On decrypt,
##    xor with 0xFF
##    multiply by "inverse mixcolumns" circulant E,B,D,9
##    deskew
##    apply shiftrows transform
##
##
##  Writes out to (%rdx), and increments or decrements it
##  Keeps track of round number mod 4 in %r8
##  Preserves xmm0
##  Clobbers xmm1-xmm5
##
.align	4
_vpaes_schedule_mangle:
	#vmr	v4, v0			# vmovdqa	%xmm0,	%xmm4	# save xmm0 for later
					# vmovdqa	.Lk_mc_forward(%rip),%xmm5
	bne	$dir, Lschedule_mangle_dec

	# encrypting
	vxor	v4, v0, v26		# vpxor	.Lk_s63(%rip),	%xmm0,	%xmm4
	addi	$out, $out, 16		# add	\$16,	%rdx
	vperm	v4, v4, v4, v25		# vpshufb	%xmm5,	%xmm4,	%xmm4
	vperm	v1, v4, v4, v25		# vpshufb	%xmm5,	%xmm4,	%xmm1
	vperm	v3, v1, v1, v25		# vpshufb	%xmm5,	%xmm1,	%xmm3
	vxor	v4, v4, v1		# vpxor		%xmm1,	%xmm4,	%xmm4
	lvx	v1, r8, r10		# vmovdqa	(%r8,%r10),	%xmm1
	vxor	v3, v3, v4		# vpxor		%xmm4,	%xmm3,	%xmm3

	vperm	v3, v3, v3, v1		# vpshufb	%xmm1,	%xmm3,	%xmm3
	addi	r8, r8, -16		# add	\$-16,	%r8
	andi.	r8, r8, 0xFF		# and	\$0xFF,	%r8

	#stvx	v3, 0, $out		# vmovdqu	%xmm3,	(%rdx)
	vperm	v1, v3, v3, $outperm	# rotate right/left
	vsel	v2, $outhead, v1, $outmask
	vmr	$outhead, v1
	stvx	v2, 0, $out
	blr

.align	4
Lschedule_mangle_dec:
	# inverse mix columns
					# lea	.Lk_dksd(%rip),%r11
	vsrb	v1, v0, v8		# vpsrlb	\$4,	%xmm4,	%xmm1	# 1 = hi
	#and	v4, v0, v9		# vpand		%xmm9,	%xmm4,	%xmm4	# 4 = lo

					# vmovdqa	0xFF(%r11),	%xmm2
	vperm	v2, v16, v16, v0	# vpshufb	%xmm4,	%xmm2,	%xmm2
					# vmovdqa	0xFF(%r11),	%xmm3
	vperm	v3, v17, v17, v1	# vpshufb	%xmm1,	%xmm3,	%xmm3
	vxor	v3, v3, v2		# vpxor		%xmm2,	%xmm3,	%xmm3
	vperm	v3, v3, v9, v25		# vpshufb	%xmm5,	%xmm3,	%xmm3

					# vmovdqa	0xFF(%r11),	%xmm2
	vperm	v2, v18, v18, v0	# vpshufb	%xmm4,	%xmm2,	%xmm2
	vxor	v2, v2, v3		# vpxor		%xmm3,	%xmm2,	%xmm2
					# vmovdqa	0xFF(%r11),	%xmm3
	vperm	v3, v19, v19, v1	# vpshufb	%xmm1,	%xmm3,	%xmm3
	vxor	v3, v3, v2		# vpxor		%xmm2,	%xmm3,	%xmm3
	vperm	v3, v3, v9, v25		# vpshufb	%xmm5,	%xmm3,	%xmm3

					# vmovdqa	0xFF(%r11),	%xmm2
	vperm	v2, v20, v20, v0	# vpshufb	%xmm4,	%xmm2,	%xmm2
	vxor	v2, v2, v3		# vpxor		%xmm3,	%xmm2,	%xmm2
					# vmovdqa	0xFF(%r11),	%xmm3
	vperm	v3, v21, v21, v1	# vpshufb	%xmm1,	%xmm3,	%xmm3
	vxor	v3, v3, v2		# vpxor		%xmm2,	%xmm3,	%xmm3

					# vmovdqa	0xFF(%r11),	%xmm2
	vperm	v2, v22, v22, v0	# vpshufb	%xmm4,	%xmm2,	%xmm2
	vperm	v3, v3, v9, v25		# vpshufb	%xmm5,	%xmm3,	%xmm3
					# vmovdqa	0xFF(%r11),	%xmm4
	vperm	v4, v23, v23, v1	# vpshufb	%xmm1,	%xmm4,	%xmm4
	lvx	v1, r8, r10		# vmovdqa	(%r8,%r10),	%xmm1
	vxor	v2, v2, v3		# vpxor		%xmm3,	%xmm2,	%xmm2
	vxor	v3, v4, v2		# vpxor		%xmm2,	%xmm4,	%xmm3

	addi	$out, $out, -16		# add	\$-16,	%rdx

	vperm	v3, v3, v3, v1		# vpshufb	%xmm1,	%xmm3,	%xmm3
	addi	r8, r8, -16		# add	\$-16,	%r8
	andi.	r8, r8, 0xFF		# and	\$0xFF,	%r8

	#stvx	v3, 0, $out		# vmovdqu	%xmm3,	(%rdx)
	vperm	v1, v3, v3, $outperm	# rotate right/left
	vsel	v2, $outhead, v1, $outmask
	vmr	$outhead, v1
	stvx	v2, 0, $out
	blr
	.long	0
	.byte	0,12,0xFF,0,0,0,0,0

.globl	.vpaes_set_encrypt_key
.align	5
.vpaes_set_encrypt_key:
	$STU	$sp,-$FRAME($sp)
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mflr	r0
	mfspr	r6, 256			# save vrsave
	stvx	v20,r10,$sp
	addi	r10,r10,32
	stvx	v21,r11,$sp
	addi	r11,r11,32
	stvx	v22,r10,$sp
	addi	r10,r10,32
	stvx	v23,r11,$sp
	addi	r11,r11,32
	stvx	v24,r10,$sp
	addi	r10,r10,32
	stvx	v25,r11,$sp
	addi	r11,r11,32
	stvx	v26,r10,$sp
	addi	r10,r10,32
	stvx	v27,r11,$sp
	addi	r11,r11,32
	stvx	v28,r10,$sp
	addi	r10,r10,32
	stvx	v29,r11,$sp
	addi	r11,r11,32
	stvx	v30,r10,$sp
	stvx	v31,r11,$sp
	stw	r6,`$FRAME-4`($sp)	# save vrsave
	li	r7, -1
	$PUSH	r0, `$FRAME+$LRSAVE`($sp)
	mtspr	256, r7			# preserve all AltiVec registers

	srwi	r9, $bits, 5		# shr	\$5,%eax
	addi	r9, r9, 6		# add	\$5,%eax
	stw	r9, 240($out)		# mov	%eax,240(%rdx)	# AES_KEY->rounds = nbits/32+5;

	cmplw	$dir, $bits, $bits	# set encrypt direction
	li	r8, 0xFF		# mov	\$0xFF,%r8d
	bl	_vpaes_schedule_core

	$POP	r0, `$FRAME+$LRSAVE`($sp)
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mtspr	256, r6			# restore vrsave
	mtlr	r0
	xor	r3, r3, r3
	lvx	v20,r10,$sp
	addi	r10,r10,32
	lvx	v21,r11,$sp
	addi	r11,r11,32
	lvx	v22,r10,$sp
	addi	r10,r10,32
	lvx	v23,r11,$sp
	addi	r11,r11,32
	lvx	v24,r10,$sp
	addi	r10,r10,32
	lvx	v25,r11,$sp
	addi	r11,r11,32
	lvx	v26,r10,$sp
	addi	r10,r10,32
	lvx	v27,r11,$sp
	addi	r11,r11,32
	lvx	v28,r10,$sp
	addi	r10,r10,32
	lvx	v29,r11,$sp
	addi	r11,r11,32
	lvx	v30,r10,$sp
	lvx	v31,r11,$sp
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,0xFF,1,0xFF,0,3,0
	.long	0
.size	.vpaes_set_encrypt_key,.-.vpaes_set_encrypt_key

.globl	.vpaes_set_decrypt_key
.align	4
.vpaes_set_decrypt_key:
	$STU	$sp,-$FRAME($sp)
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mflr	r0
	mfspr	r6, 256			# save vrsave
	stvx	v20,r10,$sp
	addi	r10,r10,32
	stvx	v21,r11,$sp
	addi	r11,r11,32
	stvx	v22,r10,$sp
	addi	r10,r10,32
	stvx	v23,r11,$sp
	addi	r11,r11,32
	stvx	v24,r10,$sp
	addi	r10,r10,32
	stvx	v25,r11,$sp
	addi	r11,r11,32
	stvx	v26,r10,$sp
	addi	r10,r10,32
	stvx	v27,r11,$sp
	addi	r11,r11,32
	stvx	v28,r10,$sp
	addi	r10,r10,32
	stvx	v29,r11,$sp
	addi	r11,r11,32
	stvx	v30,r10,$sp
	stvx	v31,r11,$sp
	stw	r6,`$FRAME-4`($sp)	# save vrsave
	li	r7, -1
	$PUSH	r0, `$FRAME+$LRSAVE`($sp)
	mtspr	256, r7			# preserve all AltiVec registers

	srwi	r9, $bits, 5		# shr	\$5,%eax
	addi	r9, r9, 6		# add	\$5,%eax
	stw	r9, 240($out)		# mov	%eax,240(%rdx)	# AES_KEY->rounds = nbits/32+5;

	slwi	r9, r9, 4		# shl	\$4,%eax
	add	$out, $out, r9		# lea	(%rdx,%rax),%rdx

	cmplwi	$dir, $bits, 0		# set decrypt direction
	srwi	r8, $bits, 1		# shr	\$1,%r8d
	andi.	r8, r8, 32		# and	\$32,%r8d
	xori	r8, r8, 32		# xor	\$32,%r8d	# nbits==192?0:32
	bl	_vpaes_schedule_core

	$POP	r0,  `$FRAME+$LRSAVE`($sp)
	li	r10,`15+6*$SIZE_T`
	li	r11,`31+6*$SIZE_T`
	mtspr	256, r6			# restore vrsave
	mtlr	r0
	xor	r3, r3, r3
	lvx	v20,r10,$sp
	addi	r10,r10,32
	lvx	v21,r11,$sp
	addi	r11,r11,32
	lvx	v22,r10,$sp
	addi	r10,r10,32
	lvx	v23,r11,$sp
	addi	r11,r11,32
	lvx	v24,r10,$sp
	addi	r10,r10,32
	lvx	v25,r11,$sp
	addi	r11,r11,32
	lvx	v26,r10,$sp
	addi	r10,r10,32
	lvx	v27,r11,$sp
	addi	r11,r11,32
	lvx	v28,r10,$sp
	addi	r10,r10,32
	lvx	v29,r11,$sp
	addi	r11,r11,32
	lvx	v30,r10,$sp
	lvx	v31,r11,$sp
	addi	$sp,$sp,$FRAME
	blr
	.long	0
	.byte	0,12,0xFF,1,0xFF,0,3,0
	.long	0
.size	.vpaes_set_decrypt_key,.-.vpaes_set_decrypt_key
___
}

my $consts=1;
foreach  (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/geo;

	# constants table endian-specific conversion
	if ($consts && m/\.long\s+(.+)\s+(\?[a-z]*)$/o) {
	    my $conv=$2;
	    my @bytes=();

	    # convert to endian-agnostic format
	    foreach (split(/,\s+/,$1)) {
		my $l = /^0/?oct:int;
		push @bytes,($l>>24)&0xFF,($l>>16)&0xFF,($l>>8)&0xFF,$l&0xFF;
	    }

	    # little-endian conversion
	    if ($flavour =~ /le$/o) {
		SWITCH: for($conv)  {
		    /\?inv/ && do   { @bytes=map($_^0xFF,@bytes); last; };
		    /\?rev/ && do   { @bytes=reverse(@bytes);    last; };
		}
	    }

	    #emit
	    print ".byte\t",join(',',map (sprintf("0x%02x",$_),@bytes)),"\n";
	    next;
	}
	$consts=0 if (m/Lconsts:/o);	# end of table

	# instructions prefixed with '?' are endian-specific and need
	# to be adjusted accordingly...
	if ($flavour =~ /le$/o) {	# little-endian
	    s/\?lvsr/lvsl/o or
	    s/\?lvsl/lvsr/o or
	    s/\?(vperm\s+v[0-9]+,\s*)(v[0-9]+,\s*)(v[0-9]+,\s*)(v[0-9]+)/$1$3$2$4/o or
	    s/\?(vsldoi\s+v[0-9]+,\s*)(v[0-9]+,)\s*(v[0-9]+,\s*)([0-9]+)/$1$3$2 16-$4/o or
	    s/\?(vspltw\s+v[0-9]+,\s*)(v[0-9]+,)\s*([0-9])/$1$2 3-$3/o;
	} else {			# big-endian
	    s/\?([a-z]+)/$1/o;
	}

	print $_,"\n";
}

close STDOUT;
