#! /usr/bin/env perl
# Copyright 2010-2016 The OpenSSL Project Authors. All Rights Reserved.
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
#
# March 2010
#
# The module implements "4-bit" GCM GHASH function and underlying
# single multiplication operation in GF(2^128). "4-bit" means that it
# uses 256 bytes per-key table [+128 bytes shared table]. Streamed
# GHASH performance was measured to be 6.67 cycles per processed byte
# on Itanium 2, which is >90% better than Microsoft compiler generated
# code. To anchor to something else sha1-ia64.pl module processes one
# byte in 5.7 cycles. On Itanium GHASH should run at ~8.5 cycles per
# byte.

# September 2010
#
# It was originally thought that it makes lesser sense to implement
# "528B" variant on Itanium 2 for following reason. Because number of
# functional units is naturally limited, it appeared impossible to
# implement "528B" loop in 4 cycles, only in 5. This would mean that
# theoretically performance improvement couldn't be more than 20%.
# But occasionally you prove yourself wrong:-) I figured out a way to
# fold couple of instructions and having freed yet another instruction
# slot by unrolling the loop... Resulting performance is 4.45 cycles
# per processed byte and 50% better than "256B" version. On original
# Itanium performance should remain the same as the "256B" version,
# i.e. ~8.5 cycles.

$output=pop and (open STDOUT,">$output" or die "can't open $output: $!");

if ($^O eq "hpux") {
    $ADDP="addp4";
    for (@ARGV) { $ADDP="add" if (/[\+DD|\-mlp]64/); }
} else { $ADDP="add"; }
for (@ARGV)  {  $big_endian=1 if (/\-DB_ENDIAN/);
                $big_endian=0 if (/\-DL_ENDIAN/);  }
if (!defined($big_endian))
             {  $big_endian=(unpack('L',pack('N',1))==1);  }

sub loop() {
my $label=shift;
my ($p16,$p17)=(shift)?("p63","p63"):("p16","p17"); # mask references to inp

# Loop is scheduled for 6 ticks on Itanium 2 and 8 on Itanium, i.e.
# in scalable manner;-) Naturally assuming data in L1 cache...
# Special note about 'dep' instruction, which is used to construct
# &rem_4bit[Zlo&0xFF]. It works, because rem_4bit is aligned at 128
# bytes boundary and lower 7 bits of its address are guaranteed to
# be zero.
$code.=<<___;
$label:
{ .mfi;	(p18)	ld8	Hlo=[Hi[1]],-8
	(p19)	dep	rem=Zlo,rem_4bitp,3,4	}
{ .mfi;	(p19)	xor	Zhi=Zhi,Hhi
	($p17)	xor	xi[1]=xi[1],in[1]	};;
{ .mfi;	(p18)	ld8	Hhi=[Hi[1]]
	(p19)	shrp	Zlo=Zhi,Zlo,4		}
{ .mfi;	(p19)	ld8	rem=[rem]
	(p18)	and	Hi[1]=mask0xFF,xi[2]	};;
{ .mmi;	($p16)	ld1	in[0]=[inp],-1
	(p18)	xor	Zlo=Zlo,Hlo
	(p19)	shr.u	Zhi=Zhi,4		}
{ .mib;	(p19)	xor	Hhi=Hhi,rem
	(p18)	add	Hi[1]=Htbl,Hi[1]	};;

{ .mfi;	(p18)	ld8	Hlo=[Hi[1]],-8
	(p18)	dep	rem=Zlo,rem_4bitp,3,4	}
{ .mfi;	(p17)	shladd	Hi[0]=xi[1],4,r0
	(p18)	xor	Zhi=Zhi,Hhi		};;
{ .mfi;	(p18)	ld8	Hhi=[Hi[1]]
	(p18)	shrp	Zlo=Zhi,Zlo,4		}
{ .mfi;	(p18)	ld8	rem=[rem]
	(p17)	and	Hi[0]=mask0xFF,Hi[0]	};;
{ .mmi;	(p16)	ld1	xi[0]=[Xi],-1
	(p18)	xor	Zlo=Zlo,Hlo
	(p18)	shr.u	Zhi=Zhi,4		}
{ .mib;	(p18)	xor	Hhi=Hhi,rem
	(p17)	add	Hi[0]=Htbl,Hi[0]
	br.ctop.sptk	$label			};;
___
}

$code=<<___;
.explicit
.text

prevfs=r2;	prevlc=r3;	prevpr=r8;
mask0xFF=r21;
rem=r22;	rem_4bitp=r23;
Xi=r24;		Htbl=r25;
inp=r26;	end=r27;
Hhi=r28;	Hlo=r29;
Zhi=r30;	Zlo=r31;

.align	128
.skip	16					// aligns loop body
.global	gcm_gmult_4bit#
.proc	gcm_gmult_4bit#
gcm_gmult_4bit:
	.prologue
{ .mmi;	.save	ar.pfs,prevfs
	alloc	prevfs=ar.pfs,2,6,0,8
	$ADDP	Xi=15,in0			// &Xi[15]
	mov	rem_4bitp=ip		}
{ .mii;	$ADDP	Htbl=8,in1			// &Htbl[0].lo
	.save	ar.lc,prevlc
	mov	prevlc=ar.lc
	.save	pr,prevpr
	mov	prevpr=pr		};;

	.body
	.rotr	in[3],xi[3],Hi[2]

{ .mib;	ld1	xi[2]=[Xi],-1			// Xi[15]
	mov	mask0xFF=0xFF
	brp.loop.imp	.Loop1,.Lend1-16};;
{ .mmi;	ld1	xi[1]=[Xi],-1			// Xi[14]
					};;
{ .mii;	shladd	Hi[1]=xi[2],4,r0
	mov	pr.rot=0xFF<<16
	mov	ar.lc=13		};;
{ .mii;	and	Hi[1]=mask0xFF,Hi[1]
	mov	ar.ec=3
	xor	Zlo=Zlo,Zlo		};;
{ .mii;	add	Hi[1]=Htbl,Hi[1]		// &Htbl[nlo].lo
	add	rem_4bitp=rem_4bit#-gcm_gmult_4bit#,rem_4bitp
	xor	Zhi=Zhi,Zhi		};;
___
	&loop	(".Loop1",1);
$code.=<<___;
.Lend1:
{ .mib;	xor	Zhi=Zhi,Hhi		};;	// modulo-scheduling artefact
{ .mib;	mux1	Zlo=Zlo,\@rev		};;
{ .mib;	mux1	Zhi=Zhi,\@rev		};;
{ .mmi;	add	Hlo=9,Xi;;			// ;; is here to prevent
	add	Hhi=1,Xi		};;	// pipeline flush on Itanium
{ .mib;	st8	[Hlo]=Zlo
	mov	pr=prevpr,0xFF	};;
{ .mib;	st8	[Hhi]=Zhi
	mov	ar.lc=prevlc
	br.ret.sptk.many	b0	};;
.endp	gcm_gmult_4bit#
___

######################################################################
# "528B" (well, "512B" actually) streamed GHASH
#
$Xip="in0";
$Htbl="in1";
$inp="in2";
$len="in3";
$rem_8bit="loc0";
$mask0xFF="loc1";
($sum,$rum) = $big_endian ? ("nop.m","nop.m") : ("sum","rum");

sub load_htable() {
    for (my $i=0;$i<8;$i++) {
	$code.=<<___;
{ .mmi;	ld8	r`16+2*$i+1`=[r8],16		// Htable[$i].hi
	ld8	r`16+2*$i`=[r9],16	}	// Htable[$i].lo
{ .mmi;	ldf8	f`32+2*$i+1`=[r10],16		// Htable[`8+$i`].hi
	ldf8	f`32+2*$i`=[r11],16		// Htable[`8+$i`].lo
___
	$code.=shift	if (($i+$#_)==7);
	$code.="\t};;\n"
    }
}

$code.=<<___;
prevsp=r3;

.align	32
.skip	16					// aligns loop body
.global	gcm_ghash_4bit#
.proc	gcm_ghash_4bit#
gcm_ghash_4bit:
	.prologue
{ .mmi;	.save	ar.pfs,prevfs
	alloc	prevfs=ar.pfs,4,2,0,0
	.vframe	prevsp
	mov	prevsp=sp
	mov	$rem_8bit=ip		};;
	.body
{ .mfi;	$ADDP	r8=0+0,$Htbl
	$ADDP	r9=0+8,$Htbl		}
{ .mfi;	$ADDP	r10=128+0,$Htbl
	$ADDP	r11=128+8,$Htbl		};;
___
	&load_htable(
	"	$ADDP	$Xip=15,$Xip",		# &Xi[15]
	"	$ADDP	$len=$len,$inp",	# &inp[len]
	"	$ADDP	$inp=15,$inp",		# &inp[15]
	"	mov	$mask0xFF=0xFF",
	"	add	sp=-512,sp",
	"	andcm	sp=sp,$mask0xFF",	# align stack frame
	"	add	r14=0,sp",
	"	add	r15=8,sp");
$code.=<<___;
{ .mmi;	$sum	1<<1				// go big-endian
	add	r8=256+0,sp
	add	r9=256+8,sp		}
{ .mmi;	add	r10=256+128+0,sp
	add	r11=256+128+8,sp
	add	$len=-17,$len		};;
___
for($i=0;$i<8;$i++) {	# generate first half of Hshr4[]
my ($rlo,$rhi)=("r".eval(16+2*$i),"r".eval(16+2*$i+1));
$code.=<<___;
{ .mmi;	st8	[r8]=$rlo,16			// Htable[$i].lo
	st8	[r9]=$rhi,16			// Htable[$i].hi
	shrp	$rlo=$rhi,$rlo,4	}//;;
{ .mmi;	stf8	[r10]=f`32+2*$i`,16		// Htable[`8+$i`].lo
	stf8	[r11]=f`32+2*$i+1`,16		// Htable[`8+$i`].hi
	shr.u	$rhi=$rhi,4		};;
{ .mmi;	st8	[r14]=$rlo,16			// Htable[$i].lo>>4
	st8	[r15]=$rhi,16		}//;;	// Htable[$i].hi>>4
___
}
$code.=<<___;
{ .mmi;	ld8	r16=[r8],16			// Htable[8].lo
	ld8	r17=[r9],16		};;	// Htable[8].hi
{ .mmi;	ld8	r18=[r8],16			// Htable[9].lo
	ld8	r19=[r9],16		}	// Htable[9].hi
{ .mmi;	rum	1<<5				// clear um.mfh
	shrp	r16=r17,r16,4		};;
___
for($i=0;$i<6;$i++) {	# generate second half of Hshr4[]
$code.=<<___;
{ .mmi;	ld8	r`20+2*$i`=[r8],16		// Htable[`10+$i`].lo
	ld8	r`20+2*$i+1`=[r9],16		// Htable[`10+$i`].hi
	shr.u	r`16+2*$i+1`=r`16+2*$i+1`,4	};;
{ .mmi;	st8	[r14]=r`16+2*$i`,16		// Htable[`8+$i`].lo>>4
	st8	[r15]=r`16+2*$i+1`,16		// Htable[`8+$i`].hi>>4
	shrp	r`18+2*$i`=r`18+2*$i+1`,r`18+2*$i`,4	}
___
}
$code.=<<___;
{ .mmi;	shr.u	r`16+2*$i+1`=r`16+2*$i+1`,4	};;
{ .mmi;	st8	[r14]=r`16+2*$i`,16		// Htable[`8+$i`].lo>>4
	st8	[r15]=r`16+2*$i+1`,16		// Htable[`8+$i`].hi>>4
	shrp	r`18+2*$i`=r`18+2*$i+1`,r`18+2*$i`,4	}
{ .mmi;	add	$Htbl=256,sp			// &Htable[0]
	add	$rem_8bit=rem_8bit#-gcm_ghash_4bit#,$rem_8bit
	shr.u	r`18+2*$i+1`=r`18+2*$i+1`,4	};;
{ .mmi;	st8	[r14]=r`18+2*$i`		// Htable[`8+$i`].lo>>4
	st8	[r15]=r`18+2*$i+1`	}	// Htable[`8+$i`].hi>>4
___

$in="r15";
@xi=("r16","r17");
@rem=("r18","r19");
($Alo,$Ahi,$Blo,$Bhi,$Zlo,$Zhi)=("r20","r21","r22","r23","r24","r25");
($Atbl,$Btbl)=("r26","r27");

$code.=<<___;	# (p16)
{ .mmi;	ld1	$in=[$inp],-1			//(p16) *inp--
	ld1	$xi[0]=[$Xip],-1		//(p16) *Xi--
	cmp.eq	p0,p6=r0,r0		};;	//	clear p6
___
push (@xi,shift(@xi)); push (@rem,shift(@rem));	# "rotate" registers

$code.=<<___;	# (p16),(p17)
{ .mmi;	ld1	$xi[0]=[$Xip],-1		//(p16) *Xi--
	xor	$xi[1]=$xi[1],$in	};;	//(p17) xi=$xi[i]^inp[i]
{ .mii;	ld1	$in=[$inp],-1			//(p16) *inp--
	dep	$Atbl=$xi[1],$Htbl,4,4		//(p17) &Htable[nlo].lo
	and	$xi[1]=-16,$xi[1]	};;	//(p17) nhi=xi&0xFF
.align	32
.LOOP:
{ .mmi;
(p6)	st8	[$Xip]=$Zhi,13
	xor	$Zlo=$Zlo,$Zlo
	add	$Btbl=$xi[1],$Htbl	};;	//(p17) &Htable[nhi].lo
___
push (@xi,shift(@xi)); push (@rem,shift(@rem));	# "rotate" registers

$code.=<<___;	# (p16),(p17),(p18)
{ .mmi;	ld8	$Alo=[$Atbl],8			//(p18) Htable[nlo].lo,&Htable[nlo].hi
	ld8	$rem[0]=[$Btbl],-256		//(p18) Htable[nhi].lo,&Hshr4[nhi].lo
	xor	$xi[1]=$xi[1],$in	};;	//(p17) xi=$xi[i]^inp[i]
{ .mfi;	ld8	$Ahi=[$Atbl]			//(p18) Htable[nlo].hi
	dep	$Atbl=$xi[1],$Htbl,4,4	}	//(p17) &Htable[nlo].lo
{ .mfi;	shladd	$rem[0]=$rem[0],4,r0		//(p18) Htable[nhi].lo<<4
	xor	$Zlo=$Zlo,$Alo		};;	//(p18) Z.lo^=Htable[nlo].lo
{ .mmi;	ld8	$Blo=[$Btbl],8			//(p18) Hshr4[nhi].lo,&Hshr4[nhi].hi
	ld1	$in=[$inp],-1		}	//(p16) *inp--
{ .mmi;	xor	$rem[0]=$rem[0],$Zlo		//(p18) Z.lo^(Htable[nhi].lo<<4)
	mov	$Zhi=$Ahi			//(p18) Z.hi^=Htable[nlo].hi
	and	$xi[1]=-16,$xi[1]	};;	//(p17) nhi=xi&0xFF
{ .mmi;	ld8	$Bhi=[$Btbl]			//(p18) Hshr4[nhi].hi
	ld1	$xi[0]=[$Xip],-1		//(p16) *Xi--
	shrp	$Zlo=$Zhi,$Zlo,8	}	//(p18) Z.lo=(Z.hi<<56)|(Z.lo>>8)
{ .mmi;	and	$rem[0]=$rem[0],$mask0xFF	//(p18) rem=($Zlo^(Htable[nhi].lo<<4))&0xFF
	add	$Btbl=$xi[1],$Htbl	};;	//(p17) &Htable[nhi]
___
push (@xi,shift(@xi)); push (@rem,shift(@rem));	# "rotate" registers

for ($i=1;$i<14;$i++) {
# Above and below fragments are derived from this one by removing
# unsuitable (p??) instructions.
$code.=<<___;	# (p16),(p17),(p18),(p19)
{ .mmi;	ld8	$Alo=[$Atbl],8			//(p18) Htable[nlo].lo,&Htable[nlo].hi
	ld8	$rem[0]=[$Btbl],-256		//(p18) Htable[nhi].lo,&Hshr4[nhi].lo
	shr.u	$Zhi=$Zhi,8		}	//(p19) Z.hi>>=8
{ .mmi;	shladd	$rem[1]=$rem[1],1,$rem_8bit	//(p19) &rem_8bit[rem]
	xor	$Zlo=$Zlo,$Blo			//(p19) Z.lo^=Hshr4[nhi].lo
	xor	$xi[1]=$xi[1],$in	};;	//(p17) xi=$xi[i]^inp[i]
{ .mmi;	ld8	$Ahi=[$Atbl]			//(p18) Htable[nlo].hi
	ld2	$rem[1]=[$rem[1]]		//(p19) rem_8bit[rem]
	dep	$Atbl=$xi[1],$Htbl,4,4	}	//(p17) &Htable[nlo].lo
{ .mmi;	shladd	$rem[0]=$rem[0],4,r0		//(p18) Htable[nhi].lo<<4
	xor	$Zlo=$Zlo,$Alo			//(p18) Z.lo^=Htable[nlo].lo
	xor	$Zhi=$Zhi,$Bhi		};;	//(p19) Z.hi^=Hshr4[nhi].hi
{ .mmi;	ld8	$Blo=[$Btbl],8			//(p18) Hshr4[nhi].lo,&Hshr4[nhi].hi
	ld1	$in=[$inp],-1			//(p16) *inp--
	shl	$rem[1]=$rem[1],48	}	//(p19) rem_8bit[rem]<<48
{ .mmi;	xor	$rem[0]=$rem[0],$Zlo		//(p18) Z.lo^(Htable[nhi].lo<<4)
	xor	$Zhi=$Zhi,$Ahi			//(p18) Z.hi^=Htable[nlo].hi
	and	$xi[1]=-16,$xi[1]	};;	//(p17) nhi=xi&0xFF
{ .mmi;	ld8	$Bhi=[$Btbl]			//(p18) Hshr4[nhi].hi
	ld1	$xi[0]=[$Xip],-1		//(p16) *Xi--
	shrp	$Zlo=$Zhi,$Zlo,8	}	//(p18) Z.lo=(Z.hi<<56)|(Z.lo>>8)
{ .mmi;	and	$rem[0]=$rem[0],$mask0xFF	//(p18) rem=($Zlo^(Htable[nhi].lo<<4))&0xFF
	xor	$Zhi=$Zhi,$rem[1]		//(p19) Z.hi^=rem_8bit[rem]<<48
	add	$Btbl=$xi[1],$Htbl	};;	//(p17) &Htable[nhi]
___
push (@xi,shift(@xi)); push (@rem,shift(@rem));	# "rotate" registers
}

$code.=<<___;	# (p17),(p18),(p19)
{ .mmi;	ld8	$Alo=[$Atbl],8			//(p18) Htable[nlo].lo,&Htable[nlo].hi
	ld8	$rem[0]=[$Btbl],-256		//(p18) Htable[nhi].lo,&Hshr4[nhi].lo
	shr.u	$Zhi=$Zhi,8		}	//(p19) Z.hi>>=8
{ .mmi;	shladd	$rem[1]=$rem[1],1,$rem_8bit	//(p19) &rem_8bit[rem]
	xor	$Zlo=$Zlo,$Blo			//(p19) Z.lo^=Hshr4[nhi].lo
	xor	$xi[1]=$xi[1],$in	};;	//(p17) xi=$xi[i]^inp[i]
{ .mmi;	ld8	$Ahi=[$Atbl]			//(p18) Htable[nlo].hi
	ld2	$rem[1]=[$rem[1]]		//(p19) rem_8bit[rem]
	dep	$Atbl=$xi[1],$Htbl,4,4	};;	//(p17) &Htable[nlo].lo
{ .mmi;	shladd	$rem[0]=$rem[0],4,r0		//(p18) Htable[nhi].lo<<4
	xor	$Zlo=$Zlo,$Alo			//(p18) Z.lo^=Htable[nlo].lo
	xor	$Zhi=$Zhi,$Bhi		};;	//(p19) Z.hi^=Hshr4[nhi].hi
{ .mmi;	ld8	$Blo=[$Btbl],8			//(p18) Hshr4[nhi].lo,&Hshr4[nhi].hi
	shl	$rem[1]=$rem[1],48	}	//(p19) rem_8bit[rem]<<48
{ .mmi;	xor	$rem[0]=$rem[0],$Zlo		//(p18) Z.lo^(Htable[nhi].lo<<4)
	xor	$Zhi=$Zhi,$Ahi			//(p18) Z.hi^=Htable[nlo].hi
	and	$xi[1]=-16,$xi[1]	};;	//(p17) nhi=xi&0xFF
{ .mmi;	ld8	$Bhi=[$Btbl]			//(p18) Hshr4[nhi].hi
	shrp	$Zlo=$Zhi,$Zlo,8	}	//(p18) Z.lo=(Z.hi<<56)|(Z.lo>>8)
{ .mmi;	and	$rem[0]=$rem[0],$mask0xFF	//(p18) rem=($Zlo^(Htable[nhi].lo<<4))&0xFF
	xor	$Zhi=$Zhi,$rem[1]		//(p19) Z.hi^=rem_8bit[rem]<<48
	add	$Btbl=$xi[1],$Htbl	};;	//(p17) &Htable[nhi]
___
push (@xi,shift(@xi)); push (@rem,shift(@rem));	# "rotate" registers

$code.=<<___;	# (p18),(p19)
{ .mfi;	ld8	$Alo=[$Atbl],8			//(p18) Htable[nlo].lo,&Htable[nlo].hi
	shr.u	$Zhi=$Zhi,8		}	//(p19) Z.hi>>=8
{ .mfi;	shladd	$rem[1]=$rem[1],1,$rem_8bit	//(p19) &rem_8bit[rem]
	xor	$Zlo=$Zlo,$Blo		};;	//(p19) Z.lo^=Hshr4[nhi].lo
{ .mfi;	ld8	$Ahi=[$Atbl]			//(p18) Htable[nlo].hi
	xor	$Zlo=$Zlo,$Alo		}	//(p18) Z.lo^=Htable[nlo].lo
{ .mfi;	ld2	$rem[1]=[$rem[1]]		//(p19) rem_8bit[rem]
	xor	$Zhi=$Zhi,$Bhi		};;	//(p19) Z.hi^=Hshr4[nhi].hi
{ .mfi;	ld8	$Blo=[$Btbl],8			//(p18) Htable[nhi].lo,&Htable[nhi].hi
	shl	$rem[1]=$rem[1],48	}	//(p19) rem_8bit[rem]<<48
{ .mfi;	shladd	$rem[0]=$Zlo,4,r0		//(p18) Z.lo<<4
	xor	$Zhi=$Zhi,$Ahi		};;	//(p18) Z.hi^=Htable[nlo].hi
{ .mfi;	ld8	$Bhi=[$Btbl]			//(p18) Htable[nhi].hi
	shrp	$Zlo=$Zhi,$Zlo,4	}	//(p18) Z.lo=(Z.hi<<60)|(Z.lo>>4)
{ .mfi;	and	$rem[0]=$rem[0],$mask0xFF	//(p18) rem=($Zlo^(Htable[nhi].lo<<4))&0xFF
	xor	$Zhi=$Zhi,$rem[1]	};;	//(p19) Z.hi^=rem_8bit[rem]<<48
___
push (@xi,shift(@xi)); push (@rem,shift(@rem));	# "rotate" registers

$code.=<<___;	# (p19)
{ .mmi;	cmp.ltu	p6,p0=$inp,$len
	add	$inp=32,$inp
	shr.u	$Zhi=$Zhi,4		}	//(p19) Z.hi>>=4
{ .mmi;	shladd	$rem[1]=$rem[1],1,$rem_8bit	//(p19) &rem_8bit[rem]
	xor	$Zlo=$Zlo,$Blo			//(p19) Z.lo^=Hshr4[nhi].lo
	add	$Xip=9,$Xip		};;	//	&Xi.lo
{ .mmi;	ld2	$rem[1]=[$rem[1]]		//(p19) rem_8bit[rem]
(p6)	ld1	$in=[$inp],-1			//[p16] *inp--
(p6)	extr.u	$xi[1]=$Zlo,8,8		}	//[p17] Xi[14]
{ .mmi;	xor	$Zhi=$Zhi,$Bhi			//(p19) Z.hi^=Hshr4[nhi].hi
(p6)	and	$xi[0]=$Zlo,$mask0xFF	};;	//[p16] Xi[15]
{ .mmi;	st8	[$Xip]=$Zlo,-8
(p6)	xor	$xi[0]=$xi[0],$in		//[p17] xi=$xi[i]^inp[i]
	shl	$rem[1]=$rem[1],48	};;	//(p19) rem_8bit[rem]<<48
{ .mmi;
(p6)	ld1	$in=[$inp],-1			//[p16] *inp--
	xor	$Zhi=$Zhi,$rem[1]		//(p19) Z.hi^=rem_8bit[rem]<<48
(p6)	dep	$Atbl=$xi[0],$Htbl,4,4	}	//[p17] &Htable[nlo].lo
{ .mib;
(p6)	and	$xi[0]=-16,$xi[0]		//[p17] nhi=xi&0xFF
(p6)	br.cond.dptk.many	.LOOP	};;

{ .mib;	st8	[$Xip]=$Zhi		};;
{ .mib;	$rum	1<<1				// return to little-endian
	.restore	sp
	mov	sp=prevsp
	br.ret.sptk.many	b0	};;
.endp	gcm_ghash_4bit#
___
$code.=<<___;
.align	128
.type	rem_4bit#,\@object
rem_4bit:
        data8	0xFF<<48, 0xFF<<48, 0xFF<<48, 0xFF<<48
        data8	0xFF<<48, 0xFF<<48, 0xFF<<48, 0xFF<<48
        data8	0xFF<<48, 0xFF<<48, 0xFF<<48, 0xFF<<48
        data8	0xFF<<48, 0xFF<<48, 0xFF<<48, 0xFF<<48
.size	rem_4bit#,128
.type	rem_8bit#,\@object
rem_8bit:
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
	data1	0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF
.size	rem_8bit#,512
stringz	"GHASH for IA64, CRYPTOGAMS by <appro\@openssl.org>"
___

$code =~ s/mux1(\s+)\S+\@rev/nop.i$1 0xFF/gm      if ($big_endian);
$code =~ s/\`([^\`]*)\`/eval $1/gem;

print $code;
close STDOUT;
