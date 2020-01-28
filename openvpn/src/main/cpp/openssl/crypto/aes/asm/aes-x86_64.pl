#! /usr/bin/env perl
# Copyright 2005-2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# Version 2.1.
#
# aes-*-cbc benchmarks are improved by >70% [compared to gcc 3.3.2 on
# Opteron 240 CPU] plus all the bells-n-whistles from 32-bit version
# [you'll notice a lot of resemblance], such as compressed S-boxes
# in little-endian byte order, prefetch of these tables in CBC mode,
# as well as avoiding L1 cache aliasing between stack frame and key
# schedule and already mentioned tables, compressed Td4...
#
# Performance in number of cycles per processed byte for 128-bit key:
#
#		ECB encrypt	ECB decrypt	CBC large chunk
# AMD64		33		43		13.0
# EM64T		38		56		18.6(*)
# Core 2	30		42		14.5(*)
# Atom		65		86		32.1(*)
#
# (*) with hyper-threading off

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$verticalspin=1;	# unlike 32-bit version $verticalspin performs
			# ~15% better on both AMD and Intel cores
$speed_limit=512;	# see aes-586.pl for details

$code=".text\n";

$s0="%eax";
$s1="%ebx";
$s2="%ecx";
$s3="%edx";
$acc0="%esi";	$mask80="%rsi";
$acc1="%edi";	$maskfe="%rdi";
$acc2="%ebp";	$mask1b="%rbp";
$inp="%r8";
$out="%r9";
$t0="%r10d";
$t1="%r11d";
$t2="%r12d";
$rnds="%r13d";
$sbox="%r14";
$key="%r15";

sub hi() { my $r=shift;	$r =~ s/%[er]([a-d])x/%\1h/;	$r; }
sub lo() { my $r=shift;	$r =~ s/%[er]([a-d])x/%\1l/;
			$r =~ s/%[er]([sd]i)/%\1l/;
			$r =~ s/%(r[0-9]+)[d]?/%\1b/;	$r; }
sub LO() { my $r=shift; $r =~ s/%r([a-z]+)/%e\1/;
			$r =~ s/%r([0-9]+)/%r\1d/;	$r; }
sub _data_word()
{ my $i;
    while(defined($i=shift)) { $code.=sprintf".long\t0x%08x,0x%08x\n",$i,$i; }
}
sub data_word()
{ my $i;
  my $last=pop(@_);
    $code.=".long\t";
    while(defined($i=shift)) { $code.=sprintf"0x%08x,",$i; }
    $code.=sprintf"0x%08x\n",$last;
}

sub data_byte()
{ my $i;
  my $last=pop(@_);
    $code.=".byte\t";
    while(defined($i=shift)) { $code.=sprintf"0x%02x,",$i&0xFF; }
    $code.=sprintf"0x%02x\n",$last&0xFF;
}

sub encvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	# favor 3-way issue Opteron pipeline...
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	0($sbox,$acc0,8),$t0
	mov	0($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t2

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	movzb	`&lo("$s3")`,$acc2
	xor	3($sbox,$acc0,8),$t0
	xor	3($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t3

	movzb	`&hi("$s3")`,$acc0
	shr	\$16,$s2
	movzb	`&hi("$s0")`,$acc2
	xor	3($sbox,$acc0,8),$t2
	shr	\$16,$s3
	xor	3($sbox,$acc2,8),$t3

	shr	\$16,$s1
	lea	16($key),$key
	shr	\$16,$s0

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	xor	2($sbox,$acc0,8),$t0
	xor	2($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	movzb	`&lo("$s1")`,$acc2
	xor	1($sbox,$acc0,8),$t0
	xor	1($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t3

	mov	12($key),$s3
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	mov	0($key),$s0
	xor	1($sbox,$acc1,8),$t2
	xor	1($sbox,$acc2,8),$t3

	mov	4($key),$s1
	mov	8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub enclastvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	movzb	2($sbox,$acc0,8),$t0
	movzb	2($sbox,$acc1,8),$t1
	movzb	2($sbox,$acc2,8),$t2

	movzb	`&lo("$s3")`,$acc0
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	movzb	2($sbox,$acc0,8),$t3
	mov	0($sbox,$acc1,8),$acc1	#$t0
	mov	0($sbox,$acc2,8),$acc2	#$t1

	and	\$0xFF,$acc1
	and	\$0xFF,$acc2

	xor	$acc1,$t0
	xor	$acc2,$t1
	shr	\$16,$s2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	shr	\$16,$s3
	mov	0($sbox,$acc0,8),$acc0	#$t2
	mov	0($sbox,$acc1,8),$acc1	#$t3

	and	\$0xFF,$acc0
	and	\$0xFF,$acc1
	shr	\$16,$s1
	xor	$acc0,$t2
	xor	$acc1,$t3
	shr	\$16,$s0

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	mov	0($sbox,$acc0,8),$acc0	#$t0
	mov	0($sbox,$acc1,8),$acc1	#$t1
	mov	0($sbox,$acc2,8),$acc2	#$t2

	and	\$0xFF,$acc0
	and	\$0xFF,$acc1
	and	\$0xFF,$acc2

	xor	$acc0,$t0
	xor	$acc1,$t1
	xor	$acc2,$t2

	movzb	`&lo("$s1")`,$acc0
	movzb	`&hi("$s3")`,$acc1
	movzb	`&hi("$s0")`,$acc2
	mov	0($sbox,$acc0,8),$acc0	#$t3
	mov	2($sbox,$acc1,8),$acc1	#$t0
	mov	2($sbox,$acc2,8),$acc2	#$t1

	and	\$0xFF,$acc0
	and	\$0xFF,$acc1
	and	\$0xFF,$acc2

	xor	$acc0,$t3
	xor	$acc1,$t0
	xor	$acc2,$t1

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	mov	16+12($key),$s3
	mov	2($sbox,$acc0,8),$acc0	#$t2
	mov	2($sbox,$acc1,8),$acc1	#$t3
	mov	16+0($key),$s0

	and	\$0xFF,$acc0
	and	\$0xFF,$acc1

	xor	$acc0,$t2
	xor	$acc1,$t3

	mov	16+4($key),$s1
	mov	16+8($key),$s2
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub encstep()
{ my ($i,@s) = @_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	if ($i==3) {
		$tmp0=$s[1];
		$tmp1=$s[2];
		$tmp2=$s[3];
	}
	$code.="	movzb	".&lo($s[0]).",$out\n";
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	lea	16($key),$key\n"	if ($i==0);

	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	mov	0($sbox,$out,8),$out\n";

	$code.="	shr	\$16,$tmp1\n";
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);
	$code.="	xor	3($sbox,$tmp0,8),$out\n";

	$code.="	movzb	".&lo($tmp1).",$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";
	$code.="	xor	4*$i($key),$out\n";

	$code.="	xor	2($sbox,$tmp1,8),$out\n";
	$code.="	xor	1($sbox,$tmp2,8),$out\n";

	$code.="	mov	$t0,$s[1]\n"		if ($i==3);
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	mov	$t2,$s[3]\n"		if ($i==3);
	$code.="\n";
}

sub enclast()
{ my ($i,@s)=@_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	if ($i==3) {
		$tmp0=$s[1];
		$tmp1=$s[2];
		$tmp2=$s[3];
	}
	$code.="	movzb	".&lo($s[0]).",$out\n";
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);

	$code.="	mov	2($sbox,$out,8),$out\n";
	$code.="	shr	\$16,$tmp1\n";
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

	$code.="	and	\$0xFF,$out\n";
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	movzb	".&lo($tmp1).",$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	mov	0($sbox,$tmp0,8),$tmp0\n";
	$code.="	mov	0($sbox,$tmp1,8),$tmp1\n";
	$code.="	mov	2($sbox,$tmp2,8),$tmp2\n";

	$code.="	and	\$0xFF,$tmp0\n";
	$code.="	and	\$0xFF,$tmp1\n";
	$code.="	and	\$0xFF,$tmp2\n";

	$code.="	xor	$tmp0,$out\n";
	$code.="	mov	$t0,$s[1]\n"		if ($i==3);
	$code.="	xor	$tmp1,$out\n";
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	xor	$tmp2,$out\n";
	$code.="	mov	$t2,$s[3]\n"		if ($i==3);
	$code.="\n";
}

$code.=<<___;
.type	_x86_64_AES_encrypt,\@abi-omnipotent
.align	16
_x86_64_AES_encrypt:
	xor	0($key),$s0			# xor with key
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3

	mov	240($key),$rnds			# load key->rounds
	sub	\$1,$rnds
	jmp	.Lenc_loop
.align	16
.Lenc_loop:
___
	if ($verticalspin) { &encvert(); }
	else {	&encstep(0,$s0,$s1,$s2,$s3);
		&encstep(1,$s1,$s2,$s3,$s0);
		&encstep(2,$s2,$s3,$s0,$s1);
		&encstep(3,$s3,$s0,$s1,$s2);
	}
$code.=<<___;
	sub	\$1,$rnds
	jnz	.Lenc_loop
___
	if ($verticalspin) { &enclastvert(); }
	else {	&enclast(0,$s0,$s1,$s2,$s3);
		&enclast(1,$s1,$s2,$s3,$s0);
		&enclast(2,$s2,$s3,$s0,$s1);
		&enclast(3,$s3,$s0,$s1,$s2);
		$code.=<<___;
		xor	16+0($key),$s0		# xor with key
		xor	16+4($key),$s1
		xor	16+8($key),$s2
		xor	16+12($key),$s3
___
	}
$code.=<<___;
	.byte	0xFF,0xFF			# rep ret
.size	_x86_64_AES_encrypt,.-_x86_64_AES_encrypt
___

# it's possible to implement this by shifting tN by 8, filling least
# significant byte with byte load and finally bswap-ing at the end,
# but such partial register load kills Core 2...
sub enccompactvert()
{ my ($t3,$t4,$t5)=("%r8d","%r9d","%r13d");

$code.=<<___;
	movzb	`&lo("$s0")`,$t0
	movzb	`&lo("$s1")`,$t1
	movzb	`&lo("$s2")`,$t2
	movzb	`&lo("$s3")`,$t3
	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	shr	\$16,$s2
	movzb	`&hi("$s3")`,$acc2
	movzb	($sbox,$t0,1),$t0
	movzb	($sbox,$t1,1),$t1
	movzb	($sbox,$t2,1),$t2
	movzb	($sbox,$t3,1),$t3

	movzb	($sbox,$acc0,1),$t4	#$t0
	movzb	`&hi("$s0")`,$acc0
	movzb	($sbox,$acc1,1),$t5	#$t1
	movzb	`&lo("$s2")`,$acc1
	movzb	($sbox,$acc2,1),$acc2	#$t2
	movzb	($sbox,$acc0,1),$acc0	#$t3

	shl	\$8,$t4
	shr	\$16,$s3
	shl	\$8,$t5
	xor	$t4,$t0
	shr	\$16,$s0
	movzb	`&lo("$s3")`,$t4
	shr	\$16,$s1
	xor	$t5,$t1
	shl	\$8,$acc2
	movzb	`&lo("$s0")`,$t5
	movzb	($sbox,$acc1,1),$acc1	#$t0
	xor	$acc2,$t2

	shl	\$8,$acc0
	movzb	`&lo("$s1")`,$acc2
	shl	\$16,$acc1
	xor	$acc0,$t3
	movzb	($sbox,$t4,1),$t4	#$t1
	movzb	`&hi("$s3")`,$acc0
	movzb	($sbox,$t5,1),$t5	#$t2
	xor	$acc1,$t0

	shr	\$8,$s2
	movzb	`&hi("$s0")`,$acc1
	shl	\$16,$t4
	shr	\$8,$s1
	shl	\$16,$t5
	xor	$t4,$t1
	movzb	($sbox,$acc2,1),$acc2	#$t3
	movzb	($sbox,$acc0,1),$acc0	#$t0
	movzb	($sbox,$acc1,1),$acc1	#$t1
	movzb	($sbox,$s2,1),$s3	#$t3
	movzb	($sbox,$s1,1),$s2	#$t2

	shl	\$16,$acc2
	xor	$t5,$t2
	shl	\$24,$acc0
	xor	$acc2,$t3
	shl	\$24,$acc1
	xor	$acc0,$t0
	shl	\$24,$s3
	xor	$acc1,$t1
	shl	\$24,$s2
	mov	$t0,$s0
	mov	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub enctransform_ref()
{ my $sn = shift;
  my ($acc,$r2,$tmp)=("%r8d","%r9d","%r13d");

$code.=<<___;
	mov	$sn,$acc
	and	\$0xFF,$acc
	mov	$acc,$tmp
	shr	\$7,$tmp
	lea	($sn,$sn),$r2
	sub	$tmp,$acc
	and	\$0xFF,$r2
	and	\$0xFF,$acc
	mov	$sn,$tmp
	xor	$acc,$r2

	xor	$r2,$sn
	rol	\$24,$sn
	xor	$r2,$sn
	ror	\$16,$tmp
	xor	$tmp,$sn
	ror	\$8,$tmp
	xor	$tmp,$sn
___
}

# unlike decrypt case it does not pay off to parallelize enctransform
sub enctransform()
{ my ($t3,$r20,$r21)=($acc2,"%r8d","%r9d");

$code.=<<___;
	mov	\$0xFF,$t0
	mov	\$0xFF,$t1
	and	$s0,$t0
	and	$s1,$t1
	mov	$t0,$acc0
	mov	$t1,$acc1
	shr	\$7,$t0
	lea	($s0,$s0),$r20
	shr	\$7,$t1
	lea	($s1,$s1),$r21
	sub	$t0,$acc0
	sub	$t1,$acc1
	and	\$0xFF,$r20
	and	\$0xFF,$r21
	and	\$0xFF,$acc0
	and	\$0xFF,$acc1
	mov	$s0,$t0
	mov	$s1,$t1
	xor	$acc0,$r20
	xor	$acc1,$r21

	xor	$r20,$s0
	xor	$r21,$s1
	 mov	\$0xFF,$t2
	rol	\$24,$s0
	 mov	\$0xFF,$t3
	rol	\$24,$s1
	 and	$s2,$t2
	 and	$s3,$t3
	xor	$r20,$s0
	xor	$r21,$s1
	 mov	$t2,$acc0
	ror	\$16,$t0
	 mov	$t3,$acc1
	ror	\$16,$t1
	 lea	($s2,$s2),$r20
	 shr	\$7,$t2
	xor	$t0,$s0
	 shr	\$7,$t3
	xor	$t1,$s1
	ror	\$8,$t0
	 lea	($s3,$s3),$r21
	ror	\$8,$t1
	 sub	$t2,$acc0
	 sub	$t3,$acc1
	xor	$t0,$s0
	xor	$t1,$s1

	and	\$0xFF,$r20
	and	\$0xFF,$r21
	and	\$0xFF,$acc0
	and	\$0xFF,$acc1
	mov	$s2,$t2
	mov	$s3,$t3
	xor	$acc0,$r20
	xor	$acc1,$r21

	ror	\$16,$t2
	xor	$r20,$s2
	ror	\$16,$t3
	xor	$r21,$s3
	rol	\$24,$s2
	mov	0($sbox),$acc0			# prefetch Te4
	rol	\$24,$s3
	xor	$r20,$s2
	mov	64($sbox),$acc1
	xor	$r21,$s3
	mov	128($sbox),$r20
	xor	$t2,$s2
	ror	\$8,$t2
	xor	$t3,$s3
	ror	\$8,$t3
	xor	$t2,$s2
	mov	192($sbox),$r21
	xor	$t3,$s3
___
}

$code.=<<___;
.type	_x86_64_AES_encrypt_compact,\@abi-omnipotent
.align	16
_x86_64_AES_encrypt_compact:
.cfi_startproc
	lea	128($sbox),$inp			# size optimization
	mov	0-128($inp),$acc1		# prefetch Te4
	mov	32-128($inp),$acc2
	mov	64-128($inp),$t0
	mov	96-128($inp),$t1
	mov	128-128($inp),$acc1
	mov	160-128($inp),$acc2
	mov	192-128($inp),$t0
	mov	224-128($inp),$t1
	jmp	.Lenc_loop_compact
.align	16
.Lenc_loop_compact:
		xor	0($key),$s0		# xor with key
		xor	4($key),$s1
		xor	8($key),$s2
		xor	12($key),$s3
		lea	16($key),$key
___
		&enccompactvert();
$code.=<<___;
		cmp	16(%rsp),$key
		je	.Lenc_compact_done
___
		&enctransform();
$code.=<<___;
	jmp	.Lenc_loop_compact
.align	16
.Lenc_compact_done:
	xor	0($key),$s0
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3
	.byte	0xFF,0xFF			# rep ret
.cfi_endproc
.size	_x86_64_AES_encrypt_compact,.-_x86_64_AES_encrypt_compact
___

# void AES_encrypt (const void *inp,void *out,const AES_KEY *key);
$code.=<<___;
.globl	AES_encrypt
.type	AES_encrypt,\@function,3
.align	16
.globl	asm_AES_encrypt
.hidden	asm_AES_encrypt
asm_AES_encrypt:
AES_encrypt:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15

	# allocate frame "above" key schedule
	lea	-63(%rdx),%rcx	# %rdx is key argument
	and	\$-64,%rsp
	sub	%rsp,%rcx
	neg	%rcx
	and	\$0xFF,%rcx
	sub	%rcx,%rsp
	sub	\$32,%rsp

	mov	%rsi,16(%rsp)	# save out
	mov	%rax,24(%rsp)	# save original stack pointer
.cfi_cfa_expression	%rsp+24,deref,+8
.Lenc_prologue:

	mov	%rdx,$key
	mov	240($key),$rnds	# load rounds

	mov	0(%rdi),$s0	# load input vector
	mov	4(%rdi),$s1
	mov	8(%rdi),$s2
	mov	12(%rdi),$s3

	shl	\$4,$rnds
	lea	($key,$rnds),%rbp
	mov	$key,(%rsp)	# key schedule
	mov	%rbp,8(%rsp)	# end of key schedule

	# pick Te4 copy which can't "overlap" with stack frame or key schedule
	lea	.LAES_Te+2048(%rip),$sbox
	lea	768(%rsp),%rbp
	sub	$sbox,%rbp
	and	\$0xFF,%rbp
	lea	($sbox,%rbp),$sbox

	call	_x86_64_AES_encrypt_compact

	mov	16(%rsp),$out	# restore out
	mov	24(%rsp),%rsi	# restore saved stack pointer
.cfi_def_cfa	%rsi,8
	mov	$s0,0($out)	# write output vector
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

	mov	-48(%rsi),%r15
.cfi_restore	%r15
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lenc_epilogue:
	ret
.cfi_endproc
.size	AES_encrypt,.-AES_encrypt
___

#------------------------------------------------------------------#

sub decvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	# favor 3-way issue Opteron pipeline...
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	mov	0($sbox,$acc0,8),$t0
	mov	0($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t2

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	movzb	`&lo("$s3")`,$acc2
	xor	3($sbox,$acc0,8),$t0
	xor	3($sbox,$acc1,8),$t1
	mov	0($sbox,$acc2,8),$t3

	movzb	`&hi("$s1")`,$acc0
	shr	\$16,$s0
	movzb	`&hi("$s2")`,$acc2
	xor	3($sbox,$acc0,8),$t2
	shr	\$16,$s3
	xor	3($sbox,$acc2,8),$t3

	shr	\$16,$s1
	lea	16($key),$key
	shr	\$16,$s2

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	xor	2($sbox,$acc0,8),$t0
	xor	2($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t2

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	movzb	`&lo("$s1")`,$acc2
	xor	1($sbox,$acc0,8),$t0
	xor	1($sbox,$acc1,8),$t1
	xor	2($sbox,$acc2,8),$t3

	movzb	`&hi("$s3")`,$acc0
	mov	12($key),$s3
	movzb	`&hi("$s0")`,$acc2
	xor	1($sbox,$acc0,8),$t2
	mov	0($key),$s0
	xor	1($sbox,$acc2,8),$t3

	xor	$t0,$s0
	mov	4($key),$s1
	mov	8($key),$s2
	xor	$t2,$s2
	xor	$t1,$s1
	xor	$t3,$s3
___
}

sub declastvert()
{ my $t3="%r8d";	# zaps $inp!

$code.=<<___;
	lea	2048($sbox),$sbox	# size optimization
	movzb	`&lo("$s0")`,$acc0
	movzb	`&lo("$s1")`,$acc1
	movzb	`&lo("$s2")`,$acc2
	movzb	($sbox,$acc0,1),$t0
	movzb	($sbox,$acc1,1),$t1
	movzb	($sbox,$acc2,1),$t2

	movzb	`&lo("$s3")`,$acc0
	movzb	`&hi("$s3")`,$acc1
	movzb	`&hi("$s0")`,$acc2
	movzb	($sbox,$acc0,1),$t3
	movzb	($sbox,$acc1,1),$acc1	#$t0
	movzb	($sbox,$acc2,1),$acc2	#$t1

	shl	\$8,$acc1
	shl	\$8,$acc2

	xor	$acc1,$t0
	xor	$acc2,$t1
	shr	\$16,$s3

	movzb	`&hi("$s1")`,$acc0
	movzb	`&hi("$s2")`,$acc1
	shr	\$16,$s0
	movzb	($sbox,$acc0,1),$acc0	#$t2
	movzb	($sbox,$acc1,1),$acc1	#$t3

	shl	\$8,$acc0
	shl	\$8,$acc1
	shr	\$16,$s1
	xor	$acc0,$t2
	xor	$acc1,$t3
	shr	\$16,$s2

	movzb	`&lo("$s2")`,$acc0
	movzb	`&lo("$s3")`,$acc1
	movzb	`&lo("$s0")`,$acc2
	movzb	($sbox,$acc0,1),$acc0	#$t0
	movzb	($sbox,$acc1,1),$acc1	#$t1
	movzb	($sbox,$acc2,1),$acc2	#$t2

	shl	\$16,$acc0
	shl	\$16,$acc1
	shl	\$16,$acc2

	xor	$acc0,$t0
	xor	$acc1,$t1
	xor	$acc2,$t2

	movzb	`&lo("$s1")`,$acc0
	movzb	`&hi("$s1")`,$acc1
	movzb	`&hi("$s2")`,$acc2
	movzb	($sbox,$acc0,1),$acc0	#$t3
	movzb	($sbox,$acc1,1),$acc1	#$t0
	movzb	($sbox,$acc2,1),$acc2	#$t1

	shl	\$16,$acc0
	shl	\$24,$acc1
	shl	\$24,$acc2

	xor	$acc0,$t3
	xor	$acc1,$t0
	xor	$acc2,$t1

	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	mov	16+12($key),$s3
	movzb	($sbox,$acc0,1),$acc0	#$t2
	movzb	($sbox,$acc1,1),$acc1	#$t3
	mov	16+0($key),$s0

	shl	\$24,$acc0
	shl	\$24,$acc1

	xor	$acc0,$t2
	xor	$acc1,$t3

	mov	16+4($key),$s1
	mov	16+8($key),$s2
	lea	-2048($sbox),$sbox
	xor	$t0,$s0
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

sub decstep()
{ my ($i,@s) = @_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	$code.="	mov	$s[0],$out\n"		if ($i!=3);
			$tmp1=$s[2]			if ($i==3);
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	and	\$0xFF,$out\n";

	$code.="	mov	0($sbox,$out,8),$out\n";
	$code.="	shr	\$16,$tmp1\n";
			$tmp2=$s[3]			if ($i==3);
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

			$tmp0=$s[1]			if ($i==3);
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	and	\$0xFF,$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	xor	3($sbox,$tmp0,8),$out\n";
	$code.="	xor	2($sbox,$tmp1,8),$out\n";
	$code.="	xor	1($sbox,$tmp2,8),$out\n";

	$code.="	mov	$t2,$s[1]\n"		if ($i==3);
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	mov	$t0,$s[3]\n"		if ($i==3);
	$code.="\n";
}

sub declast()
{ my ($i,@s)=@_;
  my $tmp0=$acc0;
  my $tmp1=$acc1;
  my $tmp2=$acc2;
  my $out=($t0,$t1,$t2,$s[0])[$i];

	$code.="	mov	$s[0],$out\n"		if ($i!=3);
			$tmp1=$s[2]			if ($i==3);
	$code.="	mov	$s[2],$tmp1\n"		if ($i!=3);
	$code.="	and	\$0xFF,$out\n";

	$code.="	movzb	2048($sbox,$out,1),$out\n";
	$code.="	shr	\$16,$tmp1\n";
			$tmp2=$s[3]			if ($i==3);
	$code.="	mov	$s[3],$tmp2\n"		if ($i!=3);

			$tmp0=$s[1]			if ($i==3);
	$code.="	movzb	".&hi($s[1]).",$tmp0\n";
	$code.="	and	\$0xFF,$tmp1\n";
	$code.="	shr	\$24,$tmp2\n";

	$code.="	movzb	2048($sbox,$tmp0,1),$tmp0\n";
	$code.="	movzb	2048($sbox,$tmp1,1),$tmp1\n";
	$code.="	movzb	2048($sbox,$tmp2,1),$tmp2\n";

	$code.="	shl	\$8,$tmp0\n";
	$code.="	shl	\$16,$tmp1\n";
	$code.="	shl	\$24,$tmp2\n";

	$code.="	xor	$tmp0,$out\n";
	$code.="	mov	$t2,$s[1]\n"		if ($i==3);
	$code.="	xor	$tmp1,$out\n";
	$code.="	mov	$t1,$s[2]\n"		if ($i==3);
	$code.="	xor	$tmp2,$out\n";
	$code.="	mov	$t0,$s[3]\n"		if ($i==3);
	$code.="\n";
}

$code.=<<___;
.type	_x86_64_AES_decrypt,\@abi-omnipotent
.align	16
_x86_64_AES_decrypt:
	xor	0($key),$s0			# xor with key
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3

	mov	240($key),$rnds			# load key->rounds
	sub	\$1,$rnds
	jmp	.Ldec_loop
.align	16
.Ldec_loop:
___
	if ($verticalspin) { &decvert(); }
	else {	&decstep(0,$s0,$s3,$s2,$s1);
		&decstep(1,$s1,$s0,$s3,$s2);
		&decstep(2,$s2,$s1,$s0,$s3);
		&decstep(3,$s3,$s2,$s1,$s0);
		$code.=<<___;
		lea	16($key),$key
		xor	0($key),$s0			# xor with key
		xor	4($key),$s1
		xor	8($key),$s2
		xor	12($key),$s3
___
	}
$code.=<<___;
	sub	\$1,$rnds
	jnz	.Ldec_loop
___
	if ($verticalspin) { &declastvert(); }
	else {	&declast(0,$s0,$s3,$s2,$s1);
		&declast(1,$s1,$s0,$s3,$s2);
		&declast(2,$s2,$s1,$s0,$s3);
		&declast(3,$s3,$s2,$s1,$s0);
		$code.=<<___;
		xor	16+0($key),$s0			# xor with key
		xor	16+4($key),$s1
		xor	16+8($key),$s2
		xor	16+12($key),$s3
___
	}
$code.=<<___;
	.byte	0xFF,0xFF			# rep ret
.size	_x86_64_AES_decrypt,.-_x86_64_AES_decrypt
___

sub deccompactvert()
{ my ($t3,$t4,$t5)=("%r8d","%r9d","%r13d");

$code.=<<___;
	movzb	`&lo("$s0")`,$t0
	movzb	`&lo("$s1")`,$t1
	movzb	`&lo("$s2")`,$t2
	movzb	`&lo("$s3")`,$t3
	movzb	`&hi("$s3")`,$acc0
	movzb	`&hi("$s0")`,$acc1
	shr	\$16,$s3
	movzb	`&hi("$s1")`,$acc2
	movzb	($sbox,$t0,1),$t0
	movzb	($sbox,$t1,1),$t1
	movzb	($sbox,$t2,1),$t2
	movzb	($sbox,$t3,1),$t3

	movzb	($sbox,$acc0,1),$t4	#$t0
	movzb	`&hi("$s2")`,$acc0
	movzb	($sbox,$acc1,1),$t5	#$t1
	movzb	($sbox,$acc2,1),$acc2	#$t2
	movzb	($sbox,$acc0,1),$acc0	#$t3

	shr	\$16,$s2
	shl	\$8,$t5
	shl	\$8,$t4
	movzb	`&lo("$s2")`,$acc1
	shr	\$16,$s0
	xor	$t4,$t0
	shr	\$16,$s1
	movzb	`&lo("$s3")`,$t4

	shl	\$8,$acc2
	xor	$t5,$t1
	shl	\$8,$acc0
	movzb	`&lo("$s0")`,$t5
	movzb	($sbox,$acc1,1),$acc1	#$t0
	xor	$acc2,$t2
	movzb	`&lo("$s1")`,$acc2

	shl	\$16,$acc1
	xor	$acc0,$t3
	movzb	($sbox,$t4,1),$t4	#$t1
	movzb	`&hi("$s1")`,$acc0
	movzb	($sbox,$acc2,1),$acc2	#$t3
	xor	$acc1,$t0
	movzb	($sbox,$t5,1),$t5	#$t2
	movzb	`&hi("$s2")`,$acc1

	shl	\$16,$acc2
	shl	\$16,$t4
	shl	\$16,$t5
	xor	$acc2,$t3
	movzb	`&hi("$s3")`,$acc2
	xor	$t4,$t1
	shr	\$8,$s0
	xor	$t5,$t2

	movzb	($sbox,$acc0,1),$acc0	#$t0
	movzb	($sbox,$acc1,1),$s1	#$t1
	movzb	($sbox,$acc2,1),$s2	#$t2
	movzb	($sbox,$s0,1),$s3	#$t3

	mov	$t0,$s0
	shl	\$24,$acc0
	shl	\$24,$s1
	shl	\$24,$s2
	xor	$acc0,$s0
	shl	\$24,$s3
	xor	$t1,$s1
	xor	$t2,$s2
	xor	$t3,$s3
___
}

# parallelized version! input is pair of 64-bit values: %rax=s1.s0
# and %rcx=s3.s2, output is four 32-bit values in %eax=s0, %ebx=s1,
# %ecx=s2 and %edx=s3.
sub dectransform()
{ my ($tp10,$tp20,$tp40,$tp80,$acc0)=("%rax","%r8", "%r9", "%r10","%rbx");
  my ($tp18,$tp28,$tp48,$tp88,$acc8)=("%rcx","%r11","%r12","%r13","%rdx");
  my $prefetch = shift;

$code.=<<___;
	mov	$mask80,$tp40
	mov	$mask80,$tp48
	and	$tp10,$tp40
	and	$tp18,$tp48
	mov	$tp40,$acc0
	mov	$tp48,$acc8
	shr	\$7,$tp40
	lea	($tp10,$tp10),$tp20
	shr	\$7,$tp48
	lea	($tp18,$tp18),$tp28
	sub	$tp40,$acc0
	sub	$tp48,$acc8
	and	$maskfe,$tp20
	and	$maskfe,$tp28
	and	$mask1b,$acc0
	and	$mask1b,$acc8
	xor	$acc0,$tp20
	xor	$acc8,$tp28
	mov	$mask80,$tp80
	mov	$mask80,$tp88

	and	$tp20,$tp80
	and	$tp28,$tp88
	mov	$tp80,$acc0
	mov	$tp88,$acc8
	shr	\$7,$tp80
	lea	($tp20,$tp20),$tp40
	shr	\$7,$tp88
	lea	($tp28,$tp28),$tp48
	sub	$tp80,$acc0
	sub	$tp88,$acc8
	and	$maskfe,$tp40
	and	$maskfe,$tp48
	and	$mask1b,$acc0
	and	$mask1b,$acc8
	xor	$acc0,$tp40
	xor	$acc8,$tp48
	mov	$mask80,$tp80
	mov	$mask80,$tp88

	and	$tp40,$tp80
	and	$tp48,$tp88
	mov	$tp80,$acc0
	mov	$tp88,$acc8
	shr	\$7,$tp80
	 xor	$tp10,$tp20		# tp2^=tp1
	shr	\$7,$tp88
	 xor	$tp18,$tp28		# tp2^=tp1
	sub	$tp80,$acc0
	sub	$tp88,$acc8
	lea	($tp40,$tp40),$tp80
	lea	($tp48,$tp48),$tp88
	 xor	$tp10,$tp40		# tp4^=tp1
	 xor	$tp18,$tp48		# tp4^=tp1
	and	$maskfe,$tp80
	and	$maskfe,$tp88
	and	$mask1b,$acc0
	and	$mask1b,$acc8
	xor	$acc0,$tp80
	xor	$acc8,$tp88

	xor	$tp80,$tp10		# tp1^=tp8
	xor	$tp88,$tp18		# tp1^=tp8
	xor	$tp80,$tp20		# tp2^tp1^=tp8
	xor	$tp88,$tp28		# tp2^tp1^=tp8
	mov	$tp10,$acc0
	mov	$tp18,$acc8
	xor	$tp80,$tp40		# tp4^tp1^=tp8
	shr	\$32,$acc0
	xor	$tp88,$tp48		# tp4^tp1^=tp8
	shr	\$32,$acc8
	xor	$tp20,$tp80		# tp8^=tp8^tp2^tp1=tp2^tp1
	rol	\$8,`&LO("$tp10")`	# ROTATE(tp1^tp8,8)
	xor	$tp28,$tp88		# tp8^=tp8^tp2^tp1=tp2^tp1
	rol	\$8,`&LO("$tp18")`	# ROTATE(tp1^tp8,8)
	xor	$tp40,$tp80		# tp2^tp1^=tp8^tp4^tp1=tp8^tp4^tp2
	rol	\$8,`&LO("$acc0")`	# ROTATE(tp1^tp8,8)
	xor	$tp48,$tp88		# tp2^tp1^=tp8^tp4^tp1=tp8^tp4^tp2

	rol	\$8,`&LO("$acc8")`	# ROTATE(tp1^tp8,8)
	xor	`&LO("$tp80")`,`&LO("$tp10")`
	shr	\$32,$tp80
	xor	`&LO("$tp88")`,`&LO("$tp18")`
	shr	\$32,$tp88
	xor	`&LO("$tp80")`,`&LO("$acc0")`
	xor	`&LO("$tp88")`,`&LO("$acc8")`

	mov	$tp20,$tp80
	rol	\$24,`&LO("$tp20")`	# ROTATE(tp2^tp1^tp8,24)
	mov	$tp28,$tp88
	rol	\$24,`&LO("$tp28")`	# ROTATE(tp2^tp1^tp8,24)
	shr	\$32,$tp80
	xor	`&LO("$tp20")`,`&LO("$tp10")`
	shr	\$32,$tp88
	xor	`&LO("$tp28")`,`&LO("$tp18")`
	rol	\$24,`&LO("$tp80")`	# ROTATE(tp2^tp1^tp8,24)
	mov	$tp40,$tp20
	rol	\$24,`&LO("$tp88")`	# ROTATE(tp2^tp1^tp8,24)
	mov	$tp48,$tp28
	shr	\$32,$tp20
	xor	`&LO("$tp80")`,`&LO("$acc0")`
	shr	\$32,$tp28
	xor	`&LO("$tp88")`,`&LO("$acc8")`

	`"mov	0($sbox),$mask80"	if ($prefetch)`
	rol	\$16,`&LO("$tp40")`	# ROTATE(tp4^tp1^tp8,16)
	`"mov	64($sbox),$maskfe"	if ($prefetch)`
	rol	\$16,`&LO("$tp48")`	# ROTATE(tp4^tp1^tp8,16)
	`"mov	128($sbox),$mask1b"	if ($prefetch)`
	rol	\$16,`&LO("$tp20")`	# ROTATE(tp4^tp1^tp8,16)
	`"mov	192($sbox),$tp80"	if ($prefetch)`
	xor	`&LO("$tp40")`,`&LO("$tp10")`
	rol	\$16,`&LO("$tp28")`	# ROTATE(tp4^tp1^tp8,16)
	xor	`&LO("$tp48")`,`&LO("$tp18")`
	`"mov	256($sbox),$tp88"	if ($prefetch)`
	xor	`&LO("$tp20")`,`&LO("$acc0")`
	xor	`&LO("$tp28")`,`&LO("$acc8")`
___
}

$code.=<<___;
.type	_x86_64_AES_decrypt_compact,\@abi-omnipotent
.align	16
_x86_64_AES_decrypt_compact:
.cfi_startproc
	lea	128($sbox),$inp			# size optimization
	mov	0-128($inp),$acc1		# prefetch Td4
	mov	32-128($inp),$acc2
	mov	64-128($inp),$t0
	mov	96-128($inp),$t1
	mov	128-128($inp),$acc1
	mov	160-128($inp),$acc2
	mov	192-128($inp),$t0
	mov	224-128($inp),$t1
	jmp	.Ldec_loop_compact

.align	16
.Ldec_loop_compact:
		xor	0($key),$s0		# xor with key
		xor	4($key),$s1
		xor	8($key),$s2
		xor	12($key),$s3
		lea	16($key),$key
___
		&deccompactvert();
$code.=<<___;
		cmp	16(%rsp),$key
		je	.Ldec_compact_done

		mov	256+0($sbox),$mask80
		shl	\$32,%rbx
		shl	\$32,%rdx
		mov	256+8($sbox),$maskfe
		or	%rbx,%rax
		or	%rdx,%rcx
		mov	256+16($sbox),$mask1b
___
		&dectransform(1);
$code.=<<___;
	jmp	.Ldec_loop_compact
.align	16
.Ldec_compact_done:
	xor	0($key),$s0
	xor	4($key),$s1
	xor	8($key),$s2
	xor	12($key),$s3
	.byte	0xFF,0xFF			# rep ret
.cfi_endproc
.size	_x86_64_AES_decrypt_compact,.-_x86_64_AES_decrypt_compact
___

# void AES_decrypt (const void *inp,void *out,const AES_KEY *key);
$code.=<<___;
.globl	AES_decrypt
.type	AES_decrypt,\@function,3
.align	16
.globl	asm_AES_decrypt
.hidden	asm_AES_decrypt
asm_AES_decrypt:
AES_decrypt:
.cfi_startproc
	mov	%rsp,%rax
.cfi_def_cfa_register	%rax
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15

	# allocate frame "above" key schedule
	lea	-63(%rdx),%rcx	# %rdx is key argument
	and	\$-64,%rsp
	sub	%rsp,%rcx
	neg	%rcx
	and	\$0xFF,%rcx
	sub	%rcx,%rsp
	sub	\$32,%rsp

	mov	%rsi,16(%rsp)	# save out
	mov	%rax,24(%rsp)	# save original stack pointer
.cfi_cfa_expression	%rsp+24,deref,+8
.Ldec_prologue:

	mov	%rdx,$key
	mov	240($key),$rnds	# load rounds

	mov	0(%rdi),$s0	# load input vector
	mov	4(%rdi),$s1
	mov	8(%rdi),$s2
	mov	12(%rdi),$s3

	shl	\$4,$rnds
	lea	($key,$rnds),%rbp
	mov	$key,(%rsp)	# key schedule
	mov	%rbp,8(%rsp)	# end of key schedule

	# pick Td4 copy which can't "overlap" with stack frame or key schedule
	lea	.LAES_Td+2048(%rip),$sbox
	lea	768(%rsp),%rbp
	sub	$sbox,%rbp
	and	\$0xFF,%rbp
	lea	($sbox,%rbp),$sbox
	shr	\$3,%rbp	# recall "magic" constants!
	add	%rbp,$sbox

	call	_x86_64_AES_decrypt_compact

	mov	16(%rsp),$out	# restore out
	mov	24(%rsp),%rsi	# restore saved stack pointer
.cfi_def_cfa	%rsi,8
	mov	$s0,0($out)	# write output vector
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

	mov	-48(%rsi),%r15
.cfi_restore	%r15
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Ldec_epilogue:
	ret
.cfi_endproc
.size	AES_decrypt,.-AES_decrypt
___
#------------------------------------------------------------------#

sub enckey()
{
$code.=<<___;
	movz	%dl,%esi		# rk[i]>>0
	movzb	-128(%rbp,%rsi),%ebx
	movz	%dh,%esi		# rk[i]>>8
	shl	\$24,%ebx
	xor	%ebx,%eax

	movzb	-128(%rbp,%rsi),%ebx
	shr	\$16,%edx
	movz	%dl,%esi		# rk[i]>>16
	xor	%ebx,%eax

	movzb	-128(%rbp,%rsi),%ebx
	movz	%dh,%esi		# rk[i]>>24
	shl	\$8,%ebx
	xor	%ebx,%eax

	movzb	-128(%rbp,%rsi),%ebx
	shl	\$16,%ebx
	xor	%ebx,%eax

	xor	1024-128(%rbp,%rcx,4),%eax		# rcon
___
}

# int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
#                        AES_KEY *key)
$code.=<<___;
.globl	AES_set_encrypt_key
.type	AES_set_encrypt_key,\@function,3
.align	16
AES_set_encrypt_key:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12			# redundant, but allows to share
.cfi_push	%r12
	push	%r13			# exception handler...
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$8,%rsp
.cfi_adjust_cfa_offset	8
.Lenc_key_prologue:

	call	_x86_64_AES_set_encrypt_key

	mov	40(%rsp),%rbp
.cfi_restore	%rbp
	mov	48(%rsp),%rbx
.cfi_restore	%rbx
	add	\$56,%rsp
.cfi_adjust_cfa_offset	-56
.Lenc_key_epilogue:
	ret
.cfi_endproc
.size	AES_set_encrypt_key,.-AES_set_encrypt_key

.type	_x86_64_AES_set_encrypt_key,\@abi-omnipotent
.align	16
_x86_64_AES_set_encrypt_key:
.cfi_startproc
	mov	%esi,%ecx			# %ecx=bits
	mov	%rdi,%rsi			# %rsi=userKey
	mov	%rdx,%rdi			# %rdi=key

	test	\$-1,%rsi
	jz	.Lbadpointer
	test	\$-1,%rdi
	jz	.Lbadpointer

	lea	.LAES_Te(%rip),%rbp
	lea	2048+128(%rbp),%rbp

	# prefetch Te4
	mov	0-128(%rbp),%eax
	mov	32-128(%rbp),%ebx
	mov	64-128(%rbp),%r8d
	mov	96-128(%rbp),%edx
	mov	128-128(%rbp),%eax
	mov	160-128(%rbp),%ebx
	mov	192-128(%rbp),%r8d
	mov	224-128(%rbp),%edx

	cmp	\$128,%ecx
	je	.L10rounds
	cmp	\$192,%ecx
	je	.L12rounds
	cmp	\$256,%ecx
	je	.L14rounds
	mov	\$-2,%rax			# invalid number of bits
	jmp	.Lexit

.L10rounds:
	mov	0(%rsi),%rax			# copy first 4 dwords
	mov	8(%rsi),%rdx
	mov	%rax,0(%rdi)
	mov	%rdx,8(%rdi)

	shr	\$32,%rdx
	xor	%ecx,%ecx
	jmp	.L10shortcut
.align	4
.L10loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	12(%rdi),%edx			# rk[3]
.L10shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,16(%rdi)			# rk[4]
		xor	4(%rdi),%eax
		mov	%eax,20(%rdi)			# rk[5]
		xor	8(%rdi),%eax
		mov	%eax,24(%rdi)			# rk[6]
		xor	12(%rdi),%eax
		mov	%eax,28(%rdi)			# rk[7]
		add	\$1,%ecx
		lea	16(%rdi),%rdi
		cmp	\$10,%ecx
	jl	.L10loop

	movl	\$10,80(%rdi)			# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.L12rounds:
	mov	0(%rsi),%rax			# copy first 6 dwords
	mov	8(%rsi),%rbx
	mov	16(%rsi),%rdx
	mov	%rax,0(%rdi)
	mov	%rbx,8(%rdi)
	mov	%rdx,16(%rdi)

	shr	\$32,%rdx
	xor	%ecx,%ecx
	jmp	.L12shortcut
.align	4
.L12loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	20(%rdi),%edx			# rk[5]
.L12shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,24(%rdi)			# rk[6]
		xor	4(%rdi),%eax
		mov	%eax,28(%rdi)			# rk[7]
		xor	8(%rdi),%eax
		mov	%eax,32(%rdi)			# rk[8]
		xor	12(%rdi),%eax
		mov	%eax,36(%rdi)			# rk[9]

		cmp	\$7,%ecx
		je	.L12break
		add	\$1,%ecx

		xor	16(%rdi),%eax
		mov	%eax,40(%rdi)			# rk[10]
		xor	20(%rdi),%eax
		mov	%eax,44(%rdi)			# rk[11]

		lea	24(%rdi),%rdi
	jmp	.L12loop
.L12break:
	movl	\$12,72(%rdi)		# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.L14rounds:
	mov	0(%rsi),%rax			# copy first 8 dwords
	mov	8(%rsi),%rbx
	mov	16(%rsi),%rcx
	mov	24(%rsi),%rdx
	mov	%rax,0(%rdi)
	mov	%rbx,8(%rdi)
	mov	%rcx,16(%rdi)
	mov	%rdx,24(%rdi)

	shr	\$32,%rdx
	xor	%ecx,%ecx
	jmp	.L14shortcut
.align	4
.L14loop:
		mov	0(%rdi),%eax			# rk[0]
		mov	28(%rdi),%edx			# rk[4]
.L14shortcut:
___
		&enckey	();
$code.=<<___;
		mov	%eax,32(%rdi)			# rk[8]
		xor	4(%rdi),%eax
		mov	%eax,36(%rdi)			# rk[9]
		xor	8(%rdi),%eax
		mov	%eax,40(%rdi)			# rk[10]
		xor	12(%rdi),%eax
		mov	%eax,44(%rdi)			# rk[11]

		cmp	\$6,%ecx
		je	.L14break
		add	\$1,%ecx

		mov	%eax,%edx
		mov	16(%rdi),%eax			# rk[4]
		movz	%dl,%esi			# rk[11]>>0
		movzb	-128(%rbp,%rsi),%ebx
		movz	%dh,%esi			# rk[11]>>8
		xor	%ebx,%eax

		movzb	-128(%rbp,%rsi),%ebx
		shr	\$16,%edx
		shl	\$8,%ebx
		movz	%dl,%esi			# rk[11]>>16
		xor	%ebx,%eax

		movzb	-128(%rbp,%rsi),%ebx
		movz	%dh,%esi			# rk[11]>>24
		shl	\$16,%ebx
		xor	%ebx,%eax

		movzb	-128(%rbp,%rsi),%ebx
		shl	\$24,%ebx
		xor	%ebx,%eax

		mov	%eax,48(%rdi)			# rk[12]
		xor	20(%rdi),%eax
		mov	%eax,52(%rdi)			# rk[13]
		xor	24(%rdi),%eax
		mov	%eax,56(%rdi)			# rk[14]
		xor	28(%rdi),%eax
		mov	%eax,60(%rdi)			# rk[15]

		lea	32(%rdi),%rdi
	jmp	.L14loop
.L14break:
	movl	\$14,48(%rdi)		# setup number of rounds
	xor	%rax,%rax
	jmp	.Lexit

.Lbadpointer:
	mov	\$-1,%rax
.Lexit:
	.byte	0xFF,0xFF			# rep ret
.cfi_endproc
.size	_x86_64_AES_set_encrypt_key,.-_x86_64_AES_set_encrypt_key
___

sub deckey_ref()
{ my ($i,$ptr,$te,$td) = @_;
  my ($tp1,$tp2,$tp4,$tp8,$acc)=("%eax","%ebx","%edi","%edx","%r8d");
$code.=<<___;
	mov	$i($ptr),$tp1
	mov	$tp1,$acc
	and	\$0xFF,$acc
	mov	$acc,$tp4
	shr	\$7,$tp4
	lea	0($tp1,$tp1),$tp2
	sub	$tp4,$acc
	and	\$0xFF,$tp2
	and	\$0xFF,$acc
	xor	$tp2,$acc
	mov	$acc,$tp2

	and	\$0xFF,$acc
	mov	$acc,$tp8
	shr	\$7,$tp8
	lea	0($tp2,$tp2),$tp4
	sub	$tp8,$acc
	and	\$0xFF,$tp4
	and	\$0xFF,$acc
	 xor	$tp1,$tp2		# tp2^tp1
	xor	$tp4,$acc
	mov	$acc,$tp4

	and	\$0xFF,$acc
	mov	$acc,$tp8
	shr	\$7,$tp8
	sub	$tp8,$acc
	lea	0($tp4,$tp4),$tp8
	 xor	$tp1,$tp4		# tp4^tp1
	and	\$0xFF,$tp8
	and	\$0xFF,$acc
	xor	$acc,$tp8

	xor	$tp8,$tp1		# tp1^tp8
	rol	\$8,$tp1		# ROTATE(tp1^tp8,8)
	xor	$tp8,$tp2		# tp2^tp1^tp8
	xor	$tp8,$tp4		# tp4^tp1^tp8
	xor	$tp2,$tp8
	xor	$tp4,$tp8		# tp8^(tp8^tp4^tp1)^(tp8^tp2^tp1)=tp8^tp4^tp2

	xor	$tp8,$tp1
	rol	\$24,$tp2		# ROTATE(tp2^tp1^tp8,24)
	xor	$tp2,$tp1
	rol	\$16,$tp4		# ROTATE(tp4^tp1^tp8,16)
	xor	$tp4,$tp1

	mov	$tp1,$i($ptr)
___
}

# int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
#                        AES_KEY *key)
$code.=<<___;
.globl	AES_set_decrypt_key
.type	AES_set_decrypt_key,\@function,3
.align	16
AES_set_decrypt_key:
.cfi_startproc
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	push	%rdx			# save key schedule
.cfi_adjust_cfa_offset	8
.Ldec_key_prologue:

	call	_x86_64_AES_set_encrypt_key
	mov	(%rsp),%r8		# restore key schedule
	cmp	\$0,%eax
	jne	.Labort

	mov	240(%r8),%r14d		# pull number of rounds
	xor	%rdi,%rdi
	lea	(%rdi,%r14d,4),%rcx
	mov	%r8,%rsi
	lea	(%r8,%rcx,4),%rdi	# pointer to last chunk
.align	4
.Linvert:
		mov	0(%rsi),%rax
		mov	8(%rsi),%rbx
		mov	0(%rdi),%rcx
		mov	8(%rdi),%rdx
		mov	%rax,0(%rdi)
		mov	%rbx,8(%rdi)
		mov	%rcx,0(%rsi)
		mov	%rdx,8(%rsi)
		lea	16(%rsi),%rsi
		lea	-16(%rdi),%rdi
		cmp	%rsi,%rdi
	jne	.Linvert

	lea	.LAES_Te+2048+1024(%rip),%rax	# rcon

	mov	40(%rax),$mask80
	mov	48(%rax),$maskfe
	mov	56(%rax),$mask1b

	mov	%r8,$key
	sub	\$1,%r14d
.align	4
.Lpermute:
		lea	16($key),$key
		mov	0($key),%rax
		mov	8($key),%rcx
___
		&dectransform ();
$code.=<<___;
		mov	%eax,0($key)
		mov	%ebx,4($key)
		mov	%ecx,8($key)
		mov	%edx,12($key)
		sub	\$1,%r14d
	jnz	.Lpermute

	xor	%rax,%rax
.Labort:
	mov	8(%rsp),%r15
.cfi_restore	%r15
	mov	16(%rsp),%r14
.cfi_restore	%r14
	mov	24(%rsp),%r13
.cfi_restore	%r13
	mov	32(%rsp),%r12
.cfi_restore	%r12
	mov	40(%rsp),%rbp
.cfi_restore	%rbp
	mov	48(%rsp),%rbx
.cfi_restore	%rbx
	add	\$56,%rsp
.cfi_adjust_cfa_offset	-56
.Ldec_key_epilogue:
	ret
.cfi_endproc
.size	AES_set_decrypt_key,.-AES_set_decrypt_key
___

# void AES_cbc_encrypt (const void char *inp, unsigned char *out,
#			size_t length, const AES_KEY *key,
#			unsigned char *ivp,const int enc);
{
# stack frame layout
# -8(%rsp)		return address
my $keyp="0(%rsp)";		# one to pass as $key
my $keyend="8(%rsp)";		# &(keyp->rd_key[4*keyp->rounds])
my $_rsp="16(%rsp)";		# saved %rsp
my $_inp="24(%rsp)";		# copy of 1st parameter, inp
my $_out="32(%rsp)";		# copy of 2nd parameter, out
my $_len="40(%rsp)";		# copy of 3rd parameter, length
my $_key="48(%rsp)";		# copy of 4th parameter, key
my $_ivp="56(%rsp)";		# copy of 5th parameter, ivp
my $ivec="64(%rsp)";		# ivec[16]
my $aes_key="80(%rsp)";		# copy of aes_key
my $mark="80+240(%rsp)";	# copy of aes_key->rounds

$code.=<<___;
.globl	AES_cbc_encrypt
.type	AES_cbc_encrypt,\@function,6
.align	16
.extern	OPENSSL_ia32cap_P
.globl	asm_AES_cbc_encrypt
.hidden	asm_AES_cbc_encrypt
asm_AES_cbc_encrypt:
AES_cbc_encrypt:
.cfi_startproc
	cmp	\$0,%rdx	# check length
	je	.Lcbc_epilogue
	pushfq
# This could be .cfi_push 49, but libunwind fails on registers it does not
# recognize. See https://bugzilla.redhat.com/show_bug.cgi?id=217087.
.cfi_adjust_cfa_offset	8
	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
.Lcbc_prologue:

	cld
	mov	%r9d,%r9d	# clear upper half of enc

	lea	.LAES_Te(%rip),$sbox
	lea	.LAES_Td(%rip),%r10
	cmp	\$0,%r9
	cmoveq	%r10,$sbox

.cfi_remember_state
	mov	OPENSSL_ia32cap_P(%rip),%r10d
	cmp	\$$speed_limit,%rdx
	jb	.Lcbc_slow_prologue
	test	\$15,%rdx
	jnz	.Lcbc_slow_prologue
	bt	\$28,%r10d
	jc	.Lcbc_slow_prologue

	# allocate aligned stack frame...
	lea	-88-248(%rsp),$key
	and	\$-64,$key

	# ... and make sure it doesn't alias with AES_T[ed] modulo 4096
	mov	$sbox,%r10
	lea	2304($sbox),%r11
	mov	$key,%r12
	and	\$0xFF,%r10	# s = $sbox&0xFF
	and	\$0xFF,%r11	# e = ($sbox+2048)&0xFF
	and	\$0xFF,%r12	# p = %rsp&0xFF

	cmp	%r11,%r12	# if (p=>e) %rsp =- (p-e);
	jb	.Lcbc_te_break_out
	sub	%r11,%r12
	sub	%r12,$key
	jmp	.Lcbc_te_ok
.Lcbc_te_break_out:		# else %rsp -= (p-s)&0xFF + framesz
	sub	%r10,%r12
	and	\$0xFF,%r12
	add	\$320,%r12
	sub	%r12,$key
.align	4
.Lcbc_te_ok:

	xchg	%rsp,$key
.cfi_def_cfa_register	$key
	#add	\$8,%rsp	# reserve for return address!
	mov	$key,$_rsp	# save %rsp
.cfi_cfa_expression	$_rsp,deref,+64
.Lcbc_fast_body:
	mov	%rdi,$_inp	# save copy of inp
	mov	%rsi,$_out	# save copy of out
	mov	%rdx,$_len	# save copy of len
	mov	%rcx,$_key	# save copy of key
	mov	%r8,$_ivp	# save copy of ivp
	movl	\$0,$mark	# copy of aes_key->rounds = 0;
	mov	%r8,%rbp	# rearrange input arguments
	mov	%r9,%rbx
	mov	%rsi,$out
	mov	%rdi,$inp
	mov	%rcx,$key

	mov	240($key),%eax		# key->rounds
	# do we copy key schedule to stack?
	mov	$key,%r10
	sub	$sbox,%r10
	and	\$0xFF,%r10
	cmp	\$2304,%r10
	jb	.Lcbc_do_ecopy
	cmp	\$4096-248,%r10
	jb	.Lcbc_skip_ecopy
.align	4
.Lcbc_do_ecopy:
		mov	$key,%rsi
		lea	$aes_key,%rdi
		lea	$aes_key,$key
		mov	\$240/8,%ecx
		.long	0xFF	# rep movsq
		mov	%eax,(%rdi)	# copy aes_key->rounds
.Lcbc_skip_ecopy:
	mov	$key,$keyp	# save key pointer

	mov	\$18,%ecx
.align	4
.Lcbc_prefetch_te:
		mov	0($sbox),%r10
		mov	32($sbox),%r11
		mov	64($sbox),%r12
		mov	96($sbox),%r13
		lea	128($sbox),$sbox
		sub	\$1,%ecx
	jnz	.Lcbc_prefetch_te
	lea	-2304($sbox),$sbox

	cmp	\$0,%rbx
	je	.LFAST_DECRYPT

#----------------------------- ENCRYPT -----------------------------#
	mov	0(%rbp),$s0		# load iv
	mov	4(%rbp),$s1
	mov	8(%rbp),$s2
	mov	12(%rbp),$s3

.align	4
.Lcbc_fast_enc_loop:
		xor	0($inp),$s0
		xor	4($inp),$s1
		xor	8($inp),$s2
		xor	12($inp),$s3
		mov	$keyp,$key	# restore key
		mov	$inp,$_inp	# if ($verticalspin) save inp

		call	_x86_64_AES_encrypt

		mov	$_inp,$inp	# if ($verticalspin) restore inp
		mov	$_len,%r10
		mov	$s0,0($out)
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		lea	16($inp),$inp
		lea	16($out),$out
		sub	\$16,%r10
		test	\$-16,%r10
		mov	%r10,$_len
	jnz	.Lcbc_fast_enc_loop
	mov	$_ivp,%rbp	# restore ivp
	mov	$s0,0(%rbp)	# save ivec
	mov	$s1,4(%rbp)
	mov	$s2,8(%rbp)
	mov	$s3,12(%rbp)

	jmp	.Lcbc_fast_cleanup

#----------------------------- DECRYPT -----------------------------#
.align	16
.LFAST_DECRYPT:
	cmp	$inp,$out
	je	.Lcbc_fast_dec_in_place

	mov	%rbp,$ivec
.align	4
.Lcbc_fast_dec_loop:
		mov	0($inp),$s0	# read input
		mov	4($inp),$s1
		mov	8($inp),$s2
		mov	12($inp),$s3
		mov	$keyp,$key	# restore key
		mov	$inp,$_inp	# if ($verticalspin) save inp

		call	_x86_64_AES_decrypt

		mov	$ivec,%rbp	# load ivp
		mov	$_inp,$inp	# if ($verticalspin) restore inp
		mov	$_len,%r10	# load len
		xor	0(%rbp),$s0	# xor iv
		xor	4(%rbp),$s1
		xor	8(%rbp),$s2
		xor	12(%rbp),$s3
		mov	$inp,%rbp	# current input, next iv

		sub	\$16,%r10
		mov	%r10,$_len	# update len
		mov	%rbp,$ivec	# update ivp

		mov	$s0,0($out)	# write output
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		lea	16($inp),$inp
		lea	16($out),$out
	jnz	.Lcbc_fast_dec_loop
	mov	$_ivp,%r12		# load user ivp
	mov	0(%rbp),%r10		# load iv
	mov	8(%rbp),%r11
	mov	%r10,0(%r12)		# copy back to user
	mov	%r11,8(%r12)
	jmp	.Lcbc_fast_cleanup

.align	16
.Lcbc_fast_dec_in_place:
	mov	0(%rbp),%r10		# copy iv to stack
	mov	8(%rbp),%r11
	mov	%r10,0+$ivec
	mov	%r11,8+$ivec
.align	4
.Lcbc_fast_dec_in_place_loop:
		mov	0($inp),$s0	# load input
		mov	4($inp),$s1
		mov	8($inp),$s2
		mov	12($inp),$s3
		mov	$keyp,$key	# restore key
		mov	$inp,$_inp	# if ($verticalspin) save inp

		call	_x86_64_AES_decrypt

		mov	$_inp,$inp	# if ($verticalspin) restore inp
		mov	$_len,%r10
		xor	0+$ivec,$s0
		xor	4+$ivec,$s1
		xor	8+$ivec,$s2
		xor	12+$ivec,$s3

		mov	0($inp),%r11	# load input
		mov	8($inp),%r12
		sub	\$16,%r10
		jz	.Lcbc_fast_dec_in_place_done

		mov	%r11,0+$ivec	# copy input to iv
		mov	%r12,8+$ivec

		mov	$s0,0($out)	# save output [zaps input]
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		lea	16($inp),$inp
		lea	16($out),$out
		mov	%r10,$_len
	jmp	.Lcbc_fast_dec_in_place_loop
.Lcbc_fast_dec_in_place_done:
	mov	$_ivp,%rdi
	mov	%r11,0(%rdi)	# copy iv back to user
	mov	%r12,8(%rdi)

	mov	$s0,0($out)	# save output [zaps input]
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

.align	4
.Lcbc_fast_cleanup:
	cmpl	\$0,$mark	# was the key schedule copied?
	lea	$aes_key,%rdi
	je	.Lcbc_exit
		mov	\$240/8,%ecx
		xor	%rax,%rax
		.long	0xFF	# rep stosq

	jmp	.Lcbc_exit

#--------------------------- SLOW ROUTINE ---------------------------#
.align	16
.Lcbc_slow_prologue:
.cfi_restore_state
	# allocate aligned stack frame...
	lea	-88(%rsp),%rbp
	and	\$-64,%rbp
	# ... just "above" key schedule
	lea	-88-63(%rcx),%r10
	sub	%rbp,%r10
	neg	%r10
	and	\$0xFF,%r10
	sub	%r10,%rbp

	xchg	%rsp,%rbp
.cfi_def_cfa_register	%rbp
	#add	\$8,%rsp	# reserve for return address!
	mov	%rbp,$_rsp	# save %rsp
.cfi_cfa_expression	$_rsp,deref,+64
.Lcbc_slow_body:
	#mov	%rdi,$_inp	# save copy of inp
	#mov	%rsi,$_out	# save copy of out
	#mov	%rdx,$_len	# save copy of len
	#mov	%rcx,$_key	# save copy of key
	mov	%r8,$_ivp	# save copy of ivp
	mov	%r8,%rbp	# rearrange input arguments
	mov	%r9,%rbx
	mov	%rsi,$out
	mov	%rdi,$inp
	mov	%rcx,$key
	mov	%rdx,%r10

	mov	240($key),%eax
	mov	$key,$keyp	# save key pointer
	shl	\$4,%eax
	lea	($key,%rax),%rax
	mov	%rax,$keyend

	# pick Te4 copy which can't "overlap" with stack frame or key schedule
	lea	2048($sbox),$sbox
	lea	768-8(%rsp),%rax
	sub	$sbox,%rax
	and	\$0xFF,%rax
	lea	($sbox,%rax),$sbox

	cmp	\$0,%rbx
	je	.LSLOW_DECRYPT

#--------------------------- SLOW ENCRYPT ---------------------------#
	test	\$-16,%r10		# check upon length
	mov	0(%rbp),$s0		# load iv
	mov	4(%rbp),$s1
	mov	8(%rbp),$s2
	mov	12(%rbp),$s3
	jz	.Lcbc_slow_enc_tail	# short input...

.align	4
.Lcbc_slow_enc_loop:
		xor	0($inp),$s0
		xor	4($inp),$s1
		xor	8($inp),$s2
		xor	12($inp),$s3
		mov	$keyp,$key	# restore key
		mov	$inp,$_inp	# save inp
		mov	$out,$_out	# save out
		mov	%r10,$_len	# save len

		call	_x86_64_AES_encrypt_compact

		mov	$_inp,$inp	# restore inp
		mov	$_out,$out	# restore out
		mov	$_len,%r10	# restore len
		mov	$s0,0($out)
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		lea	16($inp),$inp
		lea	16($out),$out
		sub	\$16,%r10
		test	\$-16,%r10
	jnz	.Lcbc_slow_enc_loop
	test	\$15,%r10
	jnz	.Lcbc_slow_enc_tail
	mov	$_ivp,%rbp	# restore ivp
	mov	$s0,0(%rbp)	# save ivec
	mov	$s1,4(%rbp)
	mov	$s2,8(%rbp)
	mov	$s3,12(%rbp)

	jmp	.Lcbc_exit

.align	4
.Lcbc_slow_enc_tail:
	mov	%rax,%r11
	mov	%rcx,%r12
	mov	%r10,%rcx
	mov	$inp,%rsi
	mov	$out,%rdi
	.long	0xFF		# rep movsb
	mov	\$16,%rcx		# zero tail
	sub	%r10,%rcx
	xor	%rax,%rax
	.long	0xFF		# rep stosb
	mov	$out,$inp		# this is not a mistake!
	mov	\$16,%r10		# len=16
	mov	%r11,%rax
	mov	%r12,%rcx
	jmp	.Lcbc_slow_enc_loop	# one more spin...
#--------------------------- SLOW DECRYPT ---------------------------#
.align	16
.LSLOW_DECRYPT:
	shr	\$3,%rax
	add	%rax,$sbox		# recall "magic" constants!

	mov	0(%rbp),%r11		# copy iv to stack
	mov	8(%rbp),%r12
	mov	%r11,0+$ivec
	mov	%r12,8+$ivec

.align	4
.Lcbc_slow_dec_loop:
		mov	0($inp),$s0	# load input
		mov	4($inp),$s1
		mov	8($inp),$s2
		mov	12($inp),$s3
		mov	$keyp,$key	# restore key
		mov	$inp,$_inp	# save inp
		mov	$out,$_out	# save out
		mov	%r10,$_len	# save len

		call	_x86_64_AES_decrypt_compact

		mov	$_inp,$inp	# restore inp
		mov	$_out,$out	# restore out
		mov	$_len,%r10
		xor	0+$ivec,$s0
		xor	4+$ivec,$s1
		xor	8+$ivec,$s2
		xor	12+$ivec,$s3

		mov	0($inp),%r11	# load input
		mov	8($inp),%r12
		sub	\$16,%r10
		jc	.Lcbc_slow_dec_partial
		jz	.Lcbc_slow_dec_done

		mov	%r11,0+$ivec	# copy input to iv
		mov	%r12,8+$ivec

		mov	$s0,0($out)	# save output [can zap input]
		mov	$s1,4($out)
		mov	$s2,8($out)
		mov	$s3,12($out)

		lea	16($inp),$inp
		lea	16($out),$out
	jmp	.Lcbc_slow_dec_loop
.Lcbc_slow_dec_done:
	mov	$_ivp,%rdi
	mov	%r11,0(%rdi)		# copy iv back to user
	mov	%r12,8(%rdi)

	mov	$s0,0($out)		# save output [can zap input]
	mov	$s1,4($out)
	mov	$s2,8($out)
	mov	$s3,12($out)

	jmp	.Lcbc_exit

.align	4
.Lcbc_slow_dec_partial:
	mov	$_ivp,%rdi
	mov	%r11,0(%rdi)		# copy iv back to user
	mov	%r12,8(%rdi)

	mov	$s0,0+$ivec		# save output to stack
	mov	$s1,4+$ivec
	mov	$s2,8+$ivec
	mov	$s3,12+$ivec

	mov	$out,%rdi
	lea	$ivec,%rsi
	lea	16(%r10),%rcx
	.long	0xFF	# rep movsb
	jmp	.Lcbc_exit

.align	16
.Lcbc_exit:
	mov	$_rsp,%rsi
.cfi_def_cfa	%rsi,64
	mov	(%rsi),%r15
.cfi_restore	%r15
	mov	8(%rsi),%r14
.cfi_restore	%r14
	mov	16(%rsi),%r13
.cfi_restore	%r13
	mov	24(%rsi),%r12
.cfi_restore	%r12
	mov	32(%rsi),%rbp
.cfi_restore	%rbp
	mov	40(%rsi),%rbx
.cfi_restore	%rbx
	lea	48(%rsi),%rsp
.cfi_def_cfa	%rsp,16
.Lcbc_popfq:
	popfq
# This could be .cfi_pop 49, but libunwind fails on registers it does not
# recognize. See https://bugzilla.redhat.com/show_bug.cgi?id=217087.
.cfi_adjust_cfa_offset	-8
.Lcbc_epilogue:
	ret
.cfi_endproc
.size	AES_cbc_encrypt,.-AES_cbc_encrypt
___
}

$code.=<<___;
.align	64
.LAES_Te:
___
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);

#Te4	# four copies of Te4 to choose from to avoid L1 aliasing
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
#rcon:
$code.=<<___;
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0xFF, 0xFF
___
$code.=<<___;
.align	64
.LAES_Td:
___
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&_data_word(0xFF, 0xFF, 0xFF, 0xFF);

#Td4:	# four copies of Td4 to choose from to avoid L1 aliasing
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
$code.=<<___;
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0, 0
___
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
$code.=<<___;
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0, 0
___
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
$code.=<<___;
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0, 0
___
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
	&data_byte(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
$code.=<<___;
	.long	0xFF, 0xFF, 0xFF, 0xFF
	.long	0xFF, 0xFF, 0, 0
.asciz  "AES for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
.align	64
___

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	block_se_handler,\@abi-omnipotent
.align	16
block_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# prologue label
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lin_block_prologue

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lin_block_prologue

	mov	24(%rax),%rax		# pull saved real stack pointer

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lin_block_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	jmp	.Lcommon_seh_exit
.size	block_se_handler,.-block_se_handler

.type	key_se_handler,\@abi-omnipotent
.align	16
key_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# prologue label
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lin_key_prologue

	mov	152($context),%rax	# pull context->Rsp

	mov	4(%r11),%r10d		# HandlerData[1]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lin_key_prologue

	lea	56(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lin_key_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	jmp	.Lcommon_seh_exit
.size	key_se_handler,.-key_se_handler

.type	cbc_se_handler,\@abi-omnipotent
.align	16
cbc_se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	lea	.Lcbc_prologue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lcbc_prologue
	jb	.Lin_cbc_prologue

	lea	.Lcbc_fast_body(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lcbc_fast_body
	jb	.Lin_cbc_frame_setup

	lea	.Lcbc_slow_prologue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lcbc_slow_prologue
	jb	.Lin_cbc_body

	lea	.Lcbc_slow_body(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lcbc_slow_body
	jb	.Lin_cbc_frame_setup

.Lin_cbc_body:
	mov	152($context),%rax	# pull context->Rsp

	lea	.Lcbc_epilogue(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>=.Lcbc_epilogue
	jae	.Lin_cbc_prologue

	lea	8(%rax),%rax

	lea	.Lcbc_popfq(%rip),%r10
	cmp	%r10,%rbx		# context->Rip>=.Lcbc_popfq
	jae	.Lin_cbc_prologue

	mov	`16-8`(%rax),%rax	# biased $_rsp
	lea	56(%rax),%rax

.Lin_cbc_frame_setup:
	mov	-16(%rax),%rbx
	mov	-24(%rax),%rbp
	mov	-32(%rax),%r12
	mov	-40(%rax),%r13
	mov	-48(%rax),%r14
	mov	-56(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R15

.Lin_cbc_prologue:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

.Lcommon_seh_exit:

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$`1232/8`,%ecx		# sizeof(CONTEXT)
	.long	0xFF		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	cbc_se_handler,.-cbc_se_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_AES_encrypt
	.rva	.LSEH_end_AES_encrypt
	.rva	.LSEH_info_AES_encrypt

	.rva	.LSEH_begin_AES_decrypt
	.rva	.LSEH_end_AES_decrypt
	.rva	.LSEH_info_AES_decrypt

	.rva	.LSEH_begin_AES_set_encrypt_key
	.rva	.LSEH_end_AES_set_encrypt_key
	.rva	.LSEH_info_AES_set_encrypt_key

	.rva	.LSEH_begin_AES_set_decrypt_key
	.rva	.LSEH_end_AES_set_decrypt_key
	.rva	.LSEH_info_AES_set_decrypt_key

	.rva	.LSEH_begin_AES_cbc_encrypt
	.rva	.LSEH_end_AES_cbc_encrypt
	.rva	.LSEH_info_AES_cbc_encrypt

.section	.xdata
.align	8
.LSEH_info_AES_encrypt:
	.byte	9,0,0,0
	.rva	block_se_handler
	.rva	.Lenc_prologue,.Lenc_epilogue	# HandlerData[]
.LSEH_info_AES_decrypt:
	.byte	9,0,0,0
	.rva	block_se_handler
	.rva	.Ldec_prologue,.Ldec_epilogue	# HandlerData[]
.LSEH_info_AES_set_encrypt_key:
	.byte	9,0,0,0
	.rva	key_se_handler
	.rva	.Lenc_key_prologue,.Lenc_key_epilogue	# HandlerData[]
.LSEH_info_AES_set_decrypt_key:
	.byte	9,0,0,0
	.rva	key_se_handler
	.rva	.Ldec_key_prologue,.Ldec_key_epilogue	# HandlerData[]
.LSEH_info_AES_cbc_encrypt:
	.byte	9,0,0,0
	.rva	cbc_se_handler
___
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
