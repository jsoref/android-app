// Copyright 2004-2016 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the OpenSSL license (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// ====================================================================
// Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
// project. Rights for redistribution and usage in source and binary
// forms are granted according to the OpenSSL license.
// ====================================================================
//
// What's wrong with compiler generated code? Compiler never uses
// variable 'shr' which is pairable with 'extr'/'dep' instructions.
// Then it uses 'zxt' which is an I-type, but can be replaced with
// 'and' which in turn can be assigned to M-port [there're double as
// much M-ports as there're I-ports on Itanium 2]. By sacrificing few
// registers for small constants (255, 24 and 16) to be used with
// 'shr' and 'and' instructions I can achieve better ILP, Instruction
// Level Parallelism, and performance. This code outperforms GCC 3.3
// generated code by over factor of 2 (two), GCC 3.4 - by 70% and
// HP C - by 40%. Measured best-case scenario, i.e. aligned
// big-endian input, ECB timing on Itanium 2 is (18 + 13*rounds)
// ticks per block, or 9.25 CPU cycles per byte for 128 bit key.

// Version 1.2 mitigates the hazard of cache-timing attacks by
// a) compressing S-boxes from 8KB to 2KB+256B, b) scheduling
// references to S-boxes for L2 cache latency, c) prefetching T[ed]4
// prior last round. As result performance dropped to (26 + 15*rounds)
// ticks per block or 11 cycles per byte processed with 128-bit key.
// This is ~16% deterioration. For reference Itanium 2 L1 cache has
// 64 bytes line size and L2 - 128 bytes...

.ident	"aes-ia64.S, version 1.2"
.ident	"IA-64 ISA artwork by Andy Polyakov <appro@openssl.org>"
.explicit
.text

rk0=r8;     rk1=r9;

pfssave=r2;
lcsave=r10;
prsave=r3;
maskff=r11;
twenty4=r14;
sixteen=r15;

te00=r16;   te11=r17;   te22=r18;   te33=r19;
te01=r20;   te12=r21;   te23=r22;   te30=r23;
te02=r24;   te13=r25;   te20=r26;   te31=r27;
te03=r28;   te10=r29;   te21=r30;   te32=r31;

// these are rotating...
t0=r32;     s0=r33;
t1=r34;     s1=r35;
t2=r36;     s2=r37;
t3=r38;     s3=r39;

te0=r40;    te1=r41;    te2=r42;    te3=r43;

#if defined(_HPUX_SOURCE) && !defined(_LP64)
# define ADDP	addp4
#else
# define ADDP	add
#endif

// Offsets from Te0
#define TE0	0
#define TE2	2
#if defined(_HPUX_SOURCE) || defined(B_ENDIAN)
#define TE1	3
#define TE3	1
#else
#define TE1	1
#define TE3	3
#endif

// This implies that AES_KEY comprises 32-bit key schedule elements
// even on LP64 platforms.
#ifndef	KSZ
# define KSZ	4
# define LDKEY	ld4
#endif

.proc	_ia64_AES_encrypt#
// Input:	rk0-rk1
//		te0
//		te3	as AES_KEY->rounds!!!
//		s0-s3
//		maskff,twenty4,sixteen
// Output:	r16,r20,r24,r28 as s0-s3
// Clobber:	r16-r31,rk0-rk1,r32-r43
.align	32
_ia64_AES_encrypt:
	.prologue
	.altrp	b6
	.body
{ .mmi;	alloc	r16=ar.pfs,12,0,0,8
	LDKEY	t0=[rk0],2*KSZ
	mov	pr.rot=1<<16	}
{ .mmi;	LDKEY	t1=[rk1],2*KSZ
	add	te1=TE1,te0
	add	te3=-3,te3	};;
{ .mib;	LDKEY	t2=[rk0],2*KSZ
	mov	ar.ec=2		}
{ .mib;	LDKEY	t3=[rk1],2*KSZ
	add	te2=TE2,te0
	brp.loop.imp	.Le_top,.Le_end-16	};;

{ .mmi;	xor	s0=s0,t0
	xor	s1=s1,t1
	mov	ar.lc=te3	}
{ .mmi;	xor	s2=s2,t2
	xor	s3=s3,t3
	add	te3=TE3,te0	};;

.align	32
.Le_top:
{ .mmi;	(p0)	LDKEY	t0=[rk0],2*KSZ		// 0/0:rk[0]
	(p0)	and	te33=s3,maskff		// 0/0:s3&0xFF
	(p0)	extr.u	te22=s2,8,8	}	// 0/0:s2>>8&0xFF
{ .mmi; (p0)	LDKEY	t1=[rk1],2*KSZ		// 0/1:rk[1]
	(p0)	and	te30=s0,maskff		// 0/1:s0&0xFF
	(p0)	shr.u	te00=s0,twenty4	};;	// 0/0:s0>>24
{ .mmi;	(p0)	LDKEY	t2=[rk0],2*KSZ		// 1/2:rk[2]
	(p0)	shladd	te33=te33,3,te3		// 1/0:te0+s0>>24
	(p0)	extr.u	te23=s3,8,8	}	// 1/1:s3>>8&0xFF
{ .mmi;	(p0)	LDKEY	t3=[rk1],2*KSZ		// 1/3:rk[3]
	(p0)	shladd	te30=te30,3,te3		// 1/1:te3+s0
	(p0)	shr.u	te01=s1,twenty4	};;	// 1/1:s1>>24
{ .mmi;	(p0)	ld4	te33=[te33]		// 2/0:te3[s3&0xFF]
	(p0)	shladd	te22=te22,3,te2		// 2/0:te2+s2>>8&0xFF
	(p0)	extr.u	te20=s0,8,8	}	// 2/2:s0>>8&0xFF
{ .mmi;	(p0)	ld4	te30=[te30]		// 2/1:te3[s0]
	(p0)	shladd	te23=te23,3,te2		// 2/1:te2+s3>>8
	(p0)	shr.u	te02=s2,twenty4	};;	// 2/2:s2>>24
{ .mmi;	(p0)	ld4	te22=[te22]		// 3/0:te2[s2>>8]
	(p0)	shladd	te20=te20,3,te2		// 3/2:te2+s0>>8
	(p0)	extr.u	te21=s1,8,8	}	// 3/3:s1>>8&0xFF
{ .mmi;	(p0)	ld4	te23=[te23]		// 3/1:te2[s3>>8]
	(p0)	shladd	te00=te00,3,te0		// 3/0:te0+s0>>24
	(p0)	shr.u	te03=s3,twenty4	};;	// 3/3:s3>>24
{ .mmi;	(p0)	ld4	te20=[te20]		// 4/2:te2[s0>>8]
	(p0)	shladd	te21=te21,3,te2		// 4/3:te3+s2
	(p0)	extr.u	te11=s1,16,8	}	// 4/0:s1>>16&0xFF
{ .mmi;	(p0)	ld4	te00=[te00]		// 4/0:te0[s0>>24]
	(p0)	shladd	te01=te01,3,te0		// 4/1:te0+s1>>24
	(p0)	shr.u	te13=s3,sixteen	};;	// 4/2:s3>>16
{ .mmi;	(p0)	ld4	te21=[te21]		// 5/3:te2[s1>>8]
	(p0)	shladd	te11=te11,3,te1		// 5/0:te1+s1>>16
	(p0)	extr.u	te12=s2,16,8	}	// 5/1:s2>>16&0xFF
{ .mmi;	(p0)	ld4	te01=[te01]		// 5/1:te0[s1>>24]
	(p0)	shladd	te02=te02,3,te0		// 5/2:te0+s2>>24
	(p0)	and	te31=s1,maskff	};;	// 5/2:s1&0xFF
{ .mmi;	(p0)	ld4	te11=[te11]		// 6/0:te1[s1>>16]
	(p0)	shladd	te12=te12,3,te1		// 6/1:te1+s2>>16
	(p0)	extr.u	te10=s0,16,8	}	// 6/3:s0>>16&0xFF
{ .mmi;	(p0)	ld4	te02=[te02]		// 6/2:te0[s2>>24]
	(p0)	shladd	te03=te03,3,te0		// 6/3:te1+s0>>16
	(p0)	and	te32=s2,maskff	};;	// 6/3:s2&0xFF

{ .mmi;	(p0)	ld4	te12=[te12]		// 7/1:te1[s2>>16]
	(p0)	shladd	te31=te31,3,te3		// 7/2:te3+s1&0xFF
	(p0)	and	te13=te13,maskff}	// 7/2:s3>>16&0xFF
{ .mmi;	(p0)	ld4	te03=[te03]		// 7/3:te0[s3>>24]
	(p0)	shladd	te32=te32,3,te3		// 7/3:te3+s2
	(p0)	xor	t0=t0,te33	};;	// 7/0:
{ .mmi;	(p0)	ld4	te31=[te31]		// 8/2:te3[s1]
	(p0)	shladd	te13=te13,3,te1		// 8/2:te1+s3>>16
	(p0)	xor	t0=t0,te22	}	// 8/0:
{ .mmi;	(p0)	ld4	te32=[te32]		// 8/3:te3[s2]
	(p0)	shladd	te10=te10,3,te1		// 8/3:te1+s0>>16
	(p0)	xor	t1=t1,te30	};;	// 8/1:
{ .mmi;	(p0)	ld4	te13=[te13]		// 9/2:te1[s3>>16]
	(p0)	ld4	te10=[te10]		// 9/3:te1[s0>>16]
	(p0)	xor	t0=t0,te00	};;	// 9/0:		!L2 scheduling
{ .mmi;	(p0)	xor	t1=t1,te23		// 10[9]/1:	
	(p0)	xor	t2=t2,te20		// 10[9]/2:
	(p0)	xor	t3=t3,te21	};;	// 10[9]/3:
{ .mmi;	(p0)	xor	t0=t0,te11		// 11[10]/0:done!
	(p0)	xor	t1=t1,te01		// 11[10]/1:
	(p0)	xor	t2=t2,te02	};;	// 11[10]/2:	!L2 scheduling
{ .mmi;	(p0)	xor	t3=t3,te03		// 12[10]/3:
	(p16)	cmp.eq	p0,p17=r0,r0 	};;	// 12[10]/clear (p17)
{ .mmi;	(p0)	xor	t1=t1,te12		// 13[11]/1:done!
	(p0)	xor	t2=t2,te31		// 13[11]/2:
	(p0)	xor	t3=t3,te32	}	// 13[11]/3:
{ .mmi;	(p17)	add	te0=2048,te0		// 13[11]/
	(p17)	add	te1=2048+64-TE1,te1};;	// 13[11]/
{ .mib;	(p0)	xor	t2=t2,te13		// 14[12]/2:done!
	(p17)	add	te2=2048+128-TE2,te2}	// 14[12]/
{ .mib;	(p0)	xor	t3=t3,te10		// 14[12]/3:done!
	(p17)	add	te3=2048+192-TE3,te3	// 14[12]/
	br.ctop.sptk	.Le_top		};;
.Le_end:


{ .mmi;	ld8	te12=[te0]		// prefetch Te4
	ld8	te31=[te1]	}
{ .mmi;	ld8	te10=[te2]
	ld8	te32=[te3]	}

{ .mmi;	LDKEY	t0=[rk0],2*KSZ		// 0/0:rk[0]
	and	te33=s3,maskff		// 0/0:s3&0xFF
	extr.u	te22=s2,8,8	}	// 0/0:s2>>8&0xFF
{ .mmi; LDKEY	t1=[rk1],2*KSZ		// 0/1:rk[1]
	and	te30=s0,maskff		// 0/1:s0&0xFF
	shr.u	te00=s0,twenty4	};;	// 0/0:s0>>24
{ .mmi;	LDKEY	t2=[rk0],2*KSZ		// 1/2:rk[2]
	add	te33=te33,te0		// 1/0:te0+s0>>24
	extr.u	te23=s3,8,8	}	// 1/1:s3>>8&0xFF
{ .mmi;	LDKEY	t3=[rk1],2*KSZ		// 1/3:rk[3]
	add	te30=te30,te0		// 1/1:te0+s0
	shr.u	te01=s1,twenty4	};;	// 1/1:s1>>24
{ .mmi;	ld1	te33=[te33]		// 2/0:te0[s3&0xFF]
	add	te22=te22,te0		// 2/0:te0+s2>>8&0xFF
	extr.u	te20=s0,8,8	}	// 2/2:s0>>8&0xFF
{ .mmi;	ld1	te30=[te30]		// 2/1:te0[s0]
	add	te23=te23,te0		// 2/1:te0+s3>>8
	shr.u	te02=s2,twenty4	};;	// 2/2:s2>>24
{ .mmi;	ld1	te22=[te22]		// 3/0:te0[s2>>8]
	add	te20=te20,te0		// 3/2:te0+s0>>8
	extr.u	te21=s1,8,8	}	// 3/3:s1>>8&0xFF
{ .mmi;	ld1	te23=[te23]		// 3/1:te0[s3>>8]
	add	te00=te00,te0		// 3/0:te0+s0>>24
	shr.u	te03=s3,twenty4	};;	// 3/3:s3>>24
{ .mmi;	ld1	te20=[te20]		// 4/2:te0[s0>>8]
	add	te21=te21,te0		// 4/3:te0+s2
	extr.u	te11=s1,16,8	}	// 4/0:s1>>16&0xFF
{ .mmi;	ld1	te00=[te00]		// 4/0:te0[s0>>24]
	add	te01=te01,te0		// 4/1:te0+s1>>24
	shr.u	te13=s3,sixteen	};;	// 4/2:s3>>16
{ .mmi;	ld1	te21=[te21]		// 5/3:te0[s1>>8]
	add	te11=te11,te0		// 5/0:te0+s1>>16
	extr.u	te12=s2,16,8	}	// 5/1:s2>>16&0xFF
{ .mmi;	ld1	te01=[te01]		// 5/1:te0[s1>>24]
	add	te02=te02,te0		// 5/2:te0+s2>>24
	and	te31=s1,maskff	};;	// 5/2:s1&0xFF
{ .mmi;	ld1	te11=[te11]		// 6/0:te0[s1>>16]
	add	te12=te12,te0		// 6/1:te0+s2>>16
	extr.u	te10=s0,16,8	}	// 6/3:s0>>16&0xFF
{ .mmi;	ld1	te02=[te02]		// 6/2:te0[s2>>24]
	add	te03=te03,te0		// 6/3:te0+s0>>16
	and	te32=s2,maskff	};;	// 6/3:s2&0xFF

{ .mmi;	ld1	te12=[te12]		// 7/1:te0[s2>>16]
	add	te31=te31,te0		// 7/2:te0+s1&0xFF
	dep	te33=te22,te33,8,8}	// 7/0:
{ .mmi;	ld1	te03=[te03]		// 7/3:te0[s3>>24]
	add	te32=te32,te0		// 7/3:te0+s2
	and	te13=te13,maskff};;	// 7/2:s3>>16&0xFF
{ .mmi;	ld1	te31=[te31]		// 8/2:te0[s1]
	add	te13=te13,te0		// 8/2:te0+s3>>16
	dep	te30=te23,te30,8,8}	// 8/1:
{ .mmi;	ld1	te32=[te32]		// 8/3:te0[s2]
	add	te10=te10,te0		// 8/3:te0+s0>>16
	shl	te00=te00,twenty4};;	// 8/0:
{ .mii;	ld1	te13=[te13]		// 9/2:te0[s3>>16]
	dep	te33=te11,te33,16,8	// 9/0:
	shl	te01=te01,twenty4};;	// 9/1:
{ .mii;	ld1	te10=[te10]		// 10/3:te0[s0>>16]
	dep	te31=te20,te31,8,8	// 10/2:
	shl	te02=te02,twenty4};;	// 10/2:
{ .mii;	xor	t0=t0,te33		// 11/0:
	dep	te32=te21,te32,8,8	// 11/3:
	shl	te12=te12,sixteen};;	// 11/1:
{ .mii;	xor	r16=t0,te00		// 12/0:done!
	dep	te31=te13,te31,16,8	// 12/2:
	shl	te03=te03,twenty4};;	// 12/3:
{ .mmi;	xor	t1=t1,te01		// 13/1:
	xor	t2=t2,te02		// 13/2:
	dep	te32=te10,te32,16,8};;	// 13/3:
{ .mmi;	xor	t1=t1,te30		// 14/1:
	xor	r24=t2,te31		// 14/2:done!
	xor	t3=t3,te32	};;	// 14/3:
{ .mib;	xor	r20=t1,te12		// 15/1:done!
	xor	r28=t3,te03		// 15/3:done!
	br.ret.sptk	b6	};;
.endp	_ia64_AES_encrypt#

// void AES_encrypt (const void *in,void *out,const AES_KEY *key);
.global	AES_encrypt#
.proc	AES_encrypt#
.align	32
AES_encrypt:
	.prologue
	.save	ar.pfs,pfssave
{ .mmi;	alloc	pfssave=ar.pfs,3,1,12,0
	and	out0=3,in0
	mov	r3=ip			}
{ .mmi;	ADDP	in0=0,in0
	mov	loc0=psr.um
	ADDP	out11=KSZ*60,in2	};;	// &AES_KEY->rounds

{ .mmi;	ld4	out11=[out11]			// AES_KEY->rounds
	add	out8=(AES_Te#-AES_encrypt#),r3	// Te0
	.save	pr,prsave
	mov	prsave=pr		}
{ .mmi;	rum	1<<3				// clear um.ac
	.save	ar.lc,lcsave
	mov	lcsave=ar.lc		};;

	.body
#if defined(_HPUX_SOURCE)	// HPUX is big-endian, cut 15+15 cycles...
{ .mib; cmp.ne	p6,p0=out0,r0
	add	out0=4,in0
(p6)	br.dpnt.many	.Le_i_unaligned	};;

{ .mmi;	ld4	out1=[in0],8		// s0
	and	out9=3,in1
	mov	twenty4=24		}
{ .mmi;	ld4	out3=[out0],8		// s1
	ADDP	rk0=0,in2
	mov	sixteen=16		};;
{ .mmi;	ld4	out5=[in0]		// s2
	cmp.ne	p6,p0=out9,r0
	mov	maskff=0xFF		}
{ .mmb;	ld4	out7=[out0]		// s3
	ADDP	rk1=KSZ,in2
	br.call.sptk.many	b6=_ia64_AES_encrypt	};;

{ .mib;	ADDP	in0=4,in1
	ADDP	in1=0,in1
(p6)	br.spnt	.Le_o_unaligned		};;

{ .mii;	mov	psr.um=loc0
	mov	ar.pfs=pfssave
	mov	ar.lc=lcsave		};;
{ .mmi;	st4	[in1]=r16,8		// s0
	st4	[in0]=r20,8		// s1
	mov	pr=prsave,0xFF	};;
{ .mmb;	st4	[in1]=r24		// s2
	st4	[in0]=r28		// s3
	br.ret.sptk.many	b0	};;
#endif

.align	32
.Le_i_unaligned:
{ .mmi;	add	out0=1,in0
	add	out2=2,in0
	add	out4=3,in0	};;
{ .mmi;	ld1	r16=[in0],4
	ld1	r17=[out0],4	}//;;
{ .mmi;	ld1	r18=[out2],4
	ld1	out1=[out4],4	};;	// s0
{ .mmi;	ld1	r20=[in0],4
	ld1	r21=[out0],4	}//;;
{ .mmi;	ld1	r22=[out2],4
	ld1	out3=[out4],4	};;	// s1
{ .mmi;	ld1	r24=[in0],4
	ld1	r25=[out0],4	}//;;
{ .mmi;	ld1	r26=[out2],4
	ld1	out5=[out4],4	};;	// s2
{ .mmi;	ld1	r28=[in0]
	ld1	r29=[out0]	}//;;
{ .mmi;	ld1	r30=[out2]
	ld1	out7=[out4]	};;	// s3

{ .mii;
	dep	out1=r16,out1,24,8	//;;
	dep	out3=r20,out3,24,8	}//;;
{ .mii;	ADDP	rk0=0,in2
	dep	out5=r24,out5,24,8	//;;
	dep	out7=r28,out7,24,8	};;
{ .mii;	ADDP	rk1=KSZ,in2
	dep	out1=r17,out1,16,8	//;;
	dep	out3=r21,out3,16,8	}//;;
{ .mii;	mov	twenty4=24
	dep	out5=r25,out5,16,8	//;;
	dep	out7=r29,out7,16,8	};;
{ .mii;	mov	sixteen=16
	dep	out1=r18,out1,8,8	//;;
	dep	out3=r22,out3,8,8	}//;;
{ .mii;	mov	maskff=0xFF
	dep	out5=r26,out5,8,8	//;;
	dep	out7=r30,out7,8,8	};;

{ .mib;	br.call.sptk.many	b6=_ia64_AES_encrypt	};;

.Le_o_unaligned:
{ .mii;	ADDP	out0=0,in1
	extr.u	r17=r16,8,8			// s0
	shr.u	r19=r16,twenty4		}//;;
{ .mii;	ADDP	out1=1,in1
	extr.u	r18=r16,16,8
	shr.u	r23=r20,twenty4		}//;;	// s1
{ .mii;	ADDP	out2=2,in1
	extr.u	r21=r20,8,8
	shr.u	r22=r20,sixteen		}//;;
{ .mii;	ADDP	out3=3,in1
	extr.u	r25=r24,8,8			// s2
	shr.u	r27=r24,twenty4		};;
{ .mii;	st1	[out3]=r16,4
	extr.u	r26=r24,16,8
	shr.u	r31=r28,twenty4		}//;;	// s3
{ .mii;	st1	[out2]=r17,4
	extr.u	r29=r28,8,8
	shr.u	r30=r28,sixteen		}//;;

{ .mmi;	st1	[out1]=r18,4
	st1	[out0]=r19,4		};;
{ .mmi;	st1	[out3]=r20,4
	st1	[out2]=r21,4		}//;;
{ .mmi;	st1	[out1]=r22,4
	st1	[out0]=r23,4		};;
{ .mmi;	st1	[out3]=r24,4
	st1	[out2]=r25,4
	mov	pr=prsave,0xFF	}//;;
{ .mmi;	st1	[out1]=r26,4
	st1	[out0]=r27,4
	mov	ar.pfs=pfssave		};;
{ .mmi;	st1	[out3]=r28
	st1	[out2]=r29
	mov	ar.lc=lcsave		}//;;
{ .mmi;	st1	[out1]=r30
	st1	[out0]=r31		}
{ .mfb;	mov	psr.um=loc0			// restore user mask
	br.ret.sptk.many	b0	};;
.endp	AES_encrypt#

// *AES_decrypt are autogenerated by the following script:
#if 0
#!/usr/bin/env perl
print "// *AES_decrypt are autogenerated by the following script:\n#if 0\n";
open(PROG,'<'.$0); while(<PROG>) { print; } close(PROG);
print "#endif\n";
while(<>) {
	$process=1	if (/\.proc\s+_ia64_AES_encrypt/);
	next		if (!$process);

	#s/te00=s0/td00=s0/;	s/te00/td00/g;
	s/te11=s1/td13=s3/;	s/te11/td13/g;
	#s/te22=s2/td22=s2/;	s/te22/td22/g;
	s/te33=s3/td31=s1/;	s/te33/td31/g;

	#s/te01=s1/td01=s1/;	s/te01/td01/g;
	s/te12=s2/td10=s0/;	s/te12/td10/g;
	#s/te23=s3/td23=s3/;	s/te23/td23/g;
	s/te30=s0/td32=s2/;	s/te30/td32/g;

	#s/te02=s2/td02=s2/;	s/te02/td02/g;
	s/te13=s3/td11=s1/;	s/te13/td11/g;
	#s/te20=s0/td20=s0/;	s/te20/td20/g;
	s/te31=s1/td33=s3/;	s/te31/td33/g;

	#s/te03=s3/td03=s3/;	s/te03/td03/g;
	s/te10=s0/td12=s2/;	s/te10/td12/g;
	#s/te21=s1/td21=s1/;	s/te21/td21/g;
	s/te32=s2/td30=s0/;	s/te32/td30/g;

	s/td/te/g;

	s/AES_encrypt/AES_decrypt/g;
	s/\.Le_/.Ld_/g;
	s/AES_Te#/AES_Td#/g;

	print;

	exit		if (/\.endp\s+AES_decrypt/);
}
#endif
.proc	_ia64_AES_decrypt#
// Input:	rk0-rk1
//		te0
//		te3	as AES_KEY->rounds!!!
//		s0-s3
//		maskff,twenty4,sixteen
// Output:	r16,r20,r24,r28 as s0-s3
// Clobber:	r16-r31,rk0-rk1,r32-r43
.align	32
_ia64_AES_decrypt:
	.prologue
	.altrp	b6
	.body
{ .mmi;	alloc	r16=ar.pfs,12,0,0,8
	LDKEY	t0=[rk0],2*KSZ
	mov	pr.rot=1<<16	}
{ .mmi;	LDKEY	t1=[rk1],2*KSZ
	add	te1=TE1,te0
	add	te3=-3,te3	};;
{ .mib;	LDKEY	t2=[rk0],2*KSZ
	mov	ar.ec=2		}
{ .mib;	LDKEY	t3=[rk1],2*KSZ
	add	te2=TE2,te0
	brp.loop.imp	.Ld_top,.Ld_end-16	};;

{ .mmi;	xor	s0=s0,t0
	xor	s1=s1,t1
	mov	ar.lc=te3	}
{ .mmi;	xor	s2=s2,t2
	xor	s3=s3,t3
	add	te3=TE3,te0	};;

.align	32
.Ld_top:
{ .mmi;	(p0)	LDKEY	t0=[rk0],2*KSZ		// 0/0:rk[0]
	(p0)	and	te31=s1,maskff		// 0/0:s3&0xFF
	(p0)	extr.u	te22=s2,8,8	}	// 0/0:s2>>8&0xFF
{ .mmi; (p0)	LDKEY	t1=[rk1],2*KSZ		// 0/1:rk[1]
	(p0)	and	te32=s2,maskff		// 0/1:s0&0xFF
	(p0)	shr.u	te00=s0,twenty4	};;	// 0/0:s0>>24
{ .mmi;	(p0)	LDKEY	t2=[rk0],2*KSZ		// 1/2:rk[2]
	(p0)	shladd	te31=te31,3,te3		// 1/0:te0+s0>>24
	(p0)	extr.u	te23=s3,8,8	}	// 1/1:s3>>8&0xFF
{ .mmi;	(p0)	LDKEY	t3=[rk1],2*KSZ		// 1/3:rk[3]
	(p0)	shladd	te32=te32,3,te3		// 1/1:te3+s0
	(p0)	shr.u	te01=s1,twenty4	};;	// 1/1:s1>>24
{ .mmi;	(p0)	ld4	te31=[te31]		// 2/0:te3[s3&0xFF]
	(p0)	shladd	te22=te22,3,te2		// 2/0:te2+s2>>8&0xFF
	(p0)	extr.u	te20=s0,8,8	}	// 2/2:s0>>8&0xFF
{ .mmi;	(p0)	ld4	te32=[te32]		// 2/1:te3[s0]
	(p0)	shladd	te23=te23,3,te2		// 2/1:te2+s3>>8
	(p0)	shr.u	te02=s2,twenty4	};;	// 2/2:s2>>24
{ .mmi;	(p0)	ld4	te22=[te22]		// 3/0:te2[s2>>8]
	(p0)	shladd	te20=te20,3,te2		// 3/2:te2+s0>>8
	(p0)	extr.u	te21=s1,8,8	}	// 3/3:s1>>8&0xFF
{ .mmi;	(p0)	ld4	te23=[te23]		// 3/1:te2[s3>>8]
	(p0)	shladd	te00=te00,3,te0		// 3/0:te0+s0>>24
	(p0)	shr.u	te03=s3,twenty4	};;	// 3/3:s3>>24
{ .mmi;	(p0)	ld4	te20=[te20]		// 4/2:te2[s0>>8]
	(p0)	shladd	te21=te21,3,te2		// 4/3:te3+s2
	(p0)	extr.u	te13=s3,16,8	}	// 4/0:s1>>16&0xFF
{ .mmi;	(p0)	ld4	te00=[te00]		// 4/0:te0[s0>>24]
	(p0)	shladd	te01=te01,3,te0		// 4/1:te0+s1>>24
	(p0)	shr.u	te11=s1,sixteen	};;	// 4/2:s3>>16
{ .mmi;	(p0)	ld4	te21=[te21]		// 5/3:te2[s1>>8]
	(p0)	shladd	te13=te13,3,te1		// 5/0:te1+s1>>16
	(p0)	extr.u	te10=s0,16,8	}	// 5/1:s2>>16&0xFF
{ .mmi;	(p0)	ld4	te01=[te01]		// 5/1:te0[s1>>24]
	(p0)	shladd	te02=te02,3,te0		// 5/2:te0+s2>>24
	(p0)	and	te33=s3,maskff	};;	// 5/2:s1&0xFF
{ .mmi;	(p0)	ld4	te13=[te13]		// 6/0:te1[s1>>16]
	(p0)	shladd	te10=te10,3,te1		// 6/1:te1+s2>>16
	(p0)	extr.u	te12=s2,16,8	}	// 6/3:s0>>16&0xFF
{ .mmi;	(p0)	ld4	te02=[te02]		// 6/2:te0[s2>>24]
	(p0)	shladd	te03=te03,3,te0		// 6/3:te1+s0>>16
	(p0)	and	te30=s0,maskff	};;	// 6/3:s2&0xFF

{ .mmi;	(p0)	ld4	te10=[te10]		// 7/1:te1[s2>>16]
	(p0)	shladd	te33=te33,3,te3		// 7/2:te3+s1&0xFF
	(p0)	and	te11=te11,maskff}	// 7/2:s3>>16&0xFF
{ .mmi;	(p0)	ld4	te03=[te03]		// 7/3:te0[s3>>24]
	(p0)	shladd	te30=te30,3,te3		// 7/3:te3+s2
	(p0)	xor	t0=t0,te31	};;	// 7/0:
{ .mmi;	(p0)	ld4	te33=[te33]		// 8/2:te3[s1]
	(p0)	shladd	te11=te11,3,te1		// 8/2:te1+s3>>16
	(p0)	xor	t0=t0,te22	}	// 8/0:
{ .mmi;	(p0)	ld4	te30=[te30]		// 8/3:te3[s2]
	(p0)	shladd	te12=te12,3,te1		// 8/3:te1+s0>>16
	(p0)	xor	t1=t1,te32	};;	// 8/1:
{ .mmi;	(p0)	ld4	te11=[te11]		// 9/2:te1[s3>>16]
	(p0)	ld4	te12=[te12]		// 9/3:te1[s0>>16]
	(p0)	xor	t0=t0,te00	};;	// 9/0:		!L2 scheduling
{ .mmi;	(p0)	xor	t1=t1,te23		// 10[9]/1:	
	(p0)	xor	t2=t2,te20		// 10[9]/2:
	(p0)	xor	t3=t3,te21	};;	// 10[9]/3:
{ .mmi;	(p0)	xor	t0=t0,te13		// 11[10]/0:done!
	(p0)	xor	t1=t1,te01		// 11[10]/1:
	(p0)	xor	t2=t2,te02	};;	// 11[10]/2:	!L2 scheduling
{ .mmi;	(p0)	xor	t3=t3,te03		// 12[10]/3:
	(p16)	cmp.eq	p0,p17=r0,r0 	};;	// 12[10]/clear (p17)
{ .mmi;	(p0)	xor	t1=t1,te10		// 13[11]/1:done!
	(p0)	xor	t2=t2,te33		// 13[11]/2:
	(p0)	xor	t3=t3,te30	}	// 13[11]/3:
{ .mmi;	(p17)	add	te0=2048,te0		// 13[11]/
	(p17)	add	te1=2048+64-TE1,te1};;	// 13[11]/
{ .mib;	(p0)	xor	t2=t2,te11		// 14[12]/2:done!
	(p17)	add	te2=2048+128-TE2,te2}	// 14[12]/
{ .mib;	(p0)	xor	t3=t3,te12		// 14[12]/3:done!
	(p17)	add	te3=2048+192-TE3,te3	// 14[12]/
	br.ctop.sptk	.Ld_top		};;
.Ld_end:


{ .mmi;	ld8	te10=[te0]		// prefetch Td4
	ld8	te33=[te1]	}
{ .mmi;	ld8	te12=[te2]
	ld8	te30=[te3]	}

{ .mmi;	LDKEY	t0=[rk0],2*KSZ		// 0/0:rk[0]
	and	te31=s1,maskff		// 0/0:s3&0xFF
	extr.u	te22=s2,8,8	}	// 0/0:s2>>8&0xFF
{ .mmi; LDKEY	t1=[rk1],2*KSZ		// 0/1:rk[1]
	and	te32=s2,maskff		// 0/1:s0&0xFF
	shr.u	te00=s0,twenty4	};;	// 0/0:s0>>24
{ .mmi;	LDKEY	t2=[rk0],2*KSZ		// 1/2:rk[2]
	add	te31=te31,te0		// 1/0:te0+s0>>24
	extr.u	te23=s3,8,8	}	// 1/1:s3>>8&0xFF
{ .mmi;	LDKEY	t3=[rk1],2*KSZ		// 1/3:rk[3]
	add	te32=te32,te0		// 1/1:te0+s0
	shr.u	te01=s1,twenty4	};;	// 1/1:s1>>24
{ .mmi;	ld1	te31=[te31]		// 2/0:te0[s3&0xFF]
	add	te22=te22,te0		// 2/0:te0+s2>>8&0xFF
	extr.u	te20=s0,8,8	}	// 2/2:s0>>8&0xFF
{ .mmi;	ld1	te32=[te32]		// 2/1:te0[s0]
	add	te23=te23,te0		// 2/1:te0+s3>>8
	shr.u	te02=s2,twenty4	};;	// 2/2:s2>>24
{ .mmi;	ld1	te22=[te22]		// 3/0:te0[s2>>8]
	add	te20=te20,te0		// 3/2:te0+s0>>8
	extr.u	te21=s1,8,8	}	// 3/3:s1>>8&0xFF
{ .mmi;	ld1	te23=[te23]		// 3/1:te0[s3>>8]
	add	te00=te00,te0		// 3/0:te0+s0>>24
	shr.u	te03=s3,twenty4	};;	// 3/3:s3>>24
{ .mmi;	ld1	te20=[te20]		// 4/2:te0[s0>>8]
	add	te21=te21,te0		// 4/3:te0+s2
	extr.u	te13=s3,16,8	}	// 4/0:s1>>16&0xFF
{ .mmi;	ld1	te00=[te00]		// 4/0:te0[s0>>24]
	add	te01=te01,te0		// 4/1:te0+s1>>24
	shr.u	te11=s1,sixteen	};;	// 4/2:s3>>16
{ .mmi;	ld1	te21=[te21]		// 5/3:te0[s1>>8]
	add	te13=te13,te0		// 5/0:te0+s1>>16
	extr.u	te10=s0,16,8	}	// 5/1:s2>>16&0xFF
{ .mmi;	ld1	te01=[te01]		// 5/1:te0[s1>>24]
	add	te02=te02,te0		// 5/2:te0+s2>>24
	and	te33=s3,maskff	};;	// 5/2:s1&0xFF
{ .mmi;	ld1	te13=[te13]		// 6/0:te0[s1>>16]
	add	te10=te10,te0		// 6/1:te0+s2>>16
	extr.u	te12=s2,16,8	}	// 6/3:s0>>16&0xFF
{ .mmi;	ld1	te02=[te02]		// 6/2:te0[s2>>24]
	add	te03=te03,te0		// 6/3:te0+s0>>16
	and	te30=s0,maskff	};;	// 6/3:s2&0xFF

{ .mmi;	ld1	te10=[te10]		// 7/1:te0[s2>>16]
	add	te33=te33,te0		// 7/2:te0+s1&0xFF
	dep	te31=te22,te31,8,8}	// 7/0:
{ .mmi;	ld1	te03=[te03]		// 7/3:te0[s3>>24]
	add	te30=te30,te0		// 7/3:te0+s2
	and	te11=te11,maskff};;	// 7/2:s3>>16&0xFF
{ .mmi;	ld1	te33=[te33]		// 8/2:te0[s1]
	add	te11=te11,te0		// 8/2:te0+s3>>16
	dep	te32=te23,te32,8,8}	// 8/1:
{ .mmi;	ld1	te30=[te30]		// 8/3:te0[s2]
	add	te12=te12,te0		// 8/3:te0+s0>>16
	shl	te00=te00,twenty4};;	// 8/0:
{ .mii;	ld1	te11=[te11]		// 9/2:te0[s3>>16]
	dep	te31=te13,te31,16,8	// 9/0:
	shl	te01=te01,twenty4};;	// 9/1:
{ .mii;	ld1	te12=[te12]		// 10/3:te0[s0>>16]
	dep	te33=te20,te33,8,8	// 10/2:
	shl	te02=te02,twenty4};;	// 10/2:
{ .mii;	xor	t0=t0,te31		// 11/0:
	dep	te30=te21,te30,8,8	// 11/3:
	shl	te10=te10,sixteen};;	// 11/1:
{ .mii;	xor	r16=t0,te00		// 12/0:done!
	dep	te33=te11,te33,16,8	// 12/2:
	shl	te03=te03,twenty4};;	// 12/3:
{ .mmi;	xor	t1=t1,te01		// 13/1:
	xor	t2=t2,te02		// 13/2:
	dep	te30=te12,te30,16,8};;	// 13/3:
{ .mmi;	xor	t1=t1,te32		// 14/1:
	xor	r24=t2,te33		// 14/2:done!
	xor	t3=t3,te30	};;	// 14/3:
{ .mib;	xor	r20=t1,te10		// 15/1:done!
	xor	r28=t3,te03		// 15/3:done!
	br.ret.sptk	b6	};;
.endp	_ia64_AES_decrypt#

// void AES_decrypt (const void *in,void *out,const AES_KEY *key);
.global	AES_decrypt#
.proc	AES_decrypt#
.align	32
AES_decrypt:
	.prologue
	.save	ar.pfs,pfssave
{ .mmi;	alloc	pfssave=ar.pfs,3,1,12,0
	and	out0=3,in0
	mov	r3=ip			}
{ .mmi;	ADDP	in0=0,in0
	mov	loc0=psr.um
	ADDP	out11=KSZ*60,in2	};;	// &AES_KEY->rounds

{ .mmi;	ld4	out11=[out11]			// AES_KEY->rounds
	add	out8=(AES_Td#-AES_decrypt#),r3	// Te0
	.save	pr,prsave
	mov	prsave=pr		}
{ .mmi;	rum	1<<3				// clear um.ac
	.save	ar.lc,lcsave
	mov	lcsave=ar.lc		};;

	.body
#if defined(_HPUX_SOURCE)	// HPUX is big-endian, cut 15+15 cycles...
{ .mib; cmp.ne	p6,p0=out0,r0
	add	out0=4,in0
(p6)	br.dpnt.many	.Ld_i_unaligned	};;

{ .mmi;	ld4	out1=[in0],8		// s0
	and	out9=3,in1
	mov	twenty4=24		}
{ .mmi;	ld4	out3=[out0],8		// s1
	ADDP	rk0=0,in2
	mov	sixteen=16		};;
{ .mmi;	ld4	out5=[in0]		// s2
	cmp.ne	p6,p0=out9,r0
	mov	maskff=0xFF		}
{ .mmb;	ld4	out7=[out0]		// s3
	ADDP	rk1=KSZ,in2
	br.call.sptk.many	b6=_ia64_AES_decrypt	};;

{ .mib;	ADDP	in0=4,in1
	ADDP	in1=0,in1
(p6)	br.spnt	.Ld_o_unaligned		};;

{ .mii;	mov	psr.um=loc0
	mov	ar.pfs=pfssave
	mov	ar.lc=lcsave		};;
{ .mmi;	st4	[in1]=r16,8		// s0
	st4	[in0]=r20,8		// s1
	mov	pr=prsave,0xFF	};;
{ .mmb;	st4	[in1]=r24		// s2
	st4	[in0]=r28		// s3
	br.ret.sptk.many	b0	};;
#endif

.align	32
.Ld_i_unaligned:
{ .mmi;	add	out0=1,in0
	add	out2=2,in0
	add	out4=3,in0	};;
{ .mmi;	ld1	r16=[in0],4
	ld1	r17=[out0],4	}//;;
{ .mmi;	ld1	r18=[out2],4
	ld1	out1=[out4],4	};;	// s0
{ .mmi;	ld1	r20=[in0],4
	ld1	r21=[out0],4	}//;;
{ .mmi;	ld1	r22=[out2],4
	ld1	out3=[out4],4	};;	// s1
{ .mmi;	ld1	r24=[in0],4
	ld1	r25=[out0],4	}//;;
{ .mmi;	ld1	r26=[out2],4
	ld1	out5=[out4],4	};;	// s2
{ .mmi;	ld1	r28=[in0]
	ld1	r29=[out0]	}//;;
{ .mmi;	ld1	r30=[out2]
	ld1	out7=[out4]	};;	// s3

{ .mii;
	dep	out1=r16,out1,24,8	//;;
	dep	out3=r20,out3,24,8	}//;;
{ .mii;	ADDP	rk0=0,in2
	dep	out5=r24,out5,24,8	//;;
	dep	out7=r28,out7,24,8	};;
{ .mii;	ADDP	rk1=KSZ,in2
	dep	out1=r17,out1,16,8	//;;
	dep	out3=r21,out3,16,8	}//;;
{ .mii;	mov	twenty4=24
	dep	out5=r25,out5,16,8	//;;
	dep	out7=r29,out7,16,8	};;
{ .mii;	mov	sixteen=16
	dep	out1=r18,out1,8,8	//;;
	dep	out3=r22,out3,8,8	}//;;
{ .mii;	mov	maskff=0xFF
	dep	out5=r26,out5,8,8	//;;
	dep	out7=r30,out7,8,8	};;

{ .mib;	br.call.sptk.many	b6=_ia64_AES_decrypt	};;

.Ld_o_unaligned:
{ .mii;	ADDP	out0=0,in1
	extr.u	r17=r16,8,8			// s0
	shr.u	r19=r16,twenty4		}//;;
{ .mii;	ADDP	out1=1,in1
	extr.u	r18=r16,16,8
	shr.u	r23=r20,twenty4		}//;;	// s1
{ .mii;	ADDP	out2=2,in1
	extr.u	r21=r20,8,8
	shr.u	r22=r20,sixteen		}//;;
{ .mii;	ADDP	out3=3,in1
	extr.u	r25=r24,8,8			// s2
	shr.u	r27=r24,twenty4		};;
{ .mii;	st1	[out3]=r16,4
	extr.u	r26=r24,16,8
	shr.u	r31=r28,twenty4		}//;;	// s3
{ .mii;	st1	[out2]=r17,4
	extr.u	r29=r28,8,8
	shr.u	r30=r28,sixteen		}//;;

{ .mmi;	st1	[out1]=r18,4
	st1	[out0]=r19,4		};;
{ .mmi;	st1	[out3]=r20,4
	st1	[out2]=r21,4		}//;;
{ .mmi;	st1	[out1]=r22,4
	st1	[out0]=r23,4		};;
{ .mmi;	st1	[out3]=r24,4
	st1	[out2]=r25,4
	mov	pr=prsave,0xFF	}//;;
{ .mmi;	st1	[out1]=r26,4
	st1	[out0]=r27,4
	mov	ar.pfs=pfssave		};;
{ .mmi;	st1	[out3]=r28
	st1	[out2]=r29
	mov	ar.lc=lcsave		}//;;
{ .mmi;	st1	[out1]=r30
	st1	[out0]=r31		}
{ .mfb;	mov	psr.um=loc0			// restore user mask
	br.ret.sptk.many	b0	};;
.endp	AES_decrypt#

// leave it in .text segment...
.align	64
.global	AES_Te#
.type	AES_Te#,@object
AES_Te:	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
// Te4:
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.size	AES_Te#,2048+256	// HP-UX assembler fails to ".-AES_Te#"

.align	64
.global	AES_Td#
.type	AES_Td#,@object
AES_Td:	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
	data4	0xFF,0xFF, 0xFF,0xFF
// Td4:
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	data1	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
.size	AES_Td#,2048+256	// HP-UX assembler fails to ".-AES_Td#"
