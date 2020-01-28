#! /usr/bin/env perl
# Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# The inner loop instruction sequence and the IP/FP modifications are from
# Svend Olaf Mikkelsen.

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../perlasm");
require "x86asm.pl";
require "cbc.pl";
require "desboth.pl";

# base code is in Microsoft
# op dest, source
# format.
#

$output=pop;
open STDOUT,">$output";

&asm_init($ARGV[0]);

$L="edi";
$R="esi";
$trans="ebp";
$small_footprint=1 if (grep(/\-DOPENSSL_SMALL_FOOTPRINT/,@ARGV));
# one can discuss setting this variable to 1 unconditionally, as
# the folded loop is only 3% slower than unrolled, but >7 times smaller

&public_label("DES_SPtrans");
&static_label("des_sptrans");

&DES_encrypt_internal();
&DES_decrypt_internal();
&DES_encrypt("DES_encrypt1",1);
&DES_encrypt("DES_encrypt2",0);
&DES_encrypt3("DES_encrypt3",1);
&DES_encrypt3("DES_decrypt3",0);
&cbc("DES_ncbc_encrypt","DES_encrypt1","DES_encrypt1",0,4,5,3,5,-1);
&cbc("DES_ede3_cbc_encrypt","DES_encrypt3","DES_decrypt3",0,6,7,3,4,5);
&DES_SPtrans();

&asm_finish();

close STDOUT;

sub DES_encrypt_internal()
	{
	&function_begin_B("_x86_DES_encrypt");

	if ($small_footprint)
	    {
	    &lea("edx",&DWP(128,"ecx"));
	    &push("edx");
	    &push("ecx");
	    &set_label("eloop");
		&D_ENCRYPT(0,$L,$R,0,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		&comment("");
		&D_ENCRYPT(1,$R,$L,2,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		&comment("");
		&add("ecx",16);
		&cmp("ecx",&swtmp(1));
		&mov(&swtmp(0),"ecx");
		&jb(&label("eloop"));
	    &add("esp",8);
	    }
	else
	    {
	    &push("ecx");
	    for ($i=0; $i<16; $i+=2)
		{
		&comment("Round $i");
		&D_ENCRYPT($i,$L,$R,$i*2,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		&comment("Round ".sprintf("%d",$i+1));
		&D_ENCRYPT($i+1,$R,$L,($i+1)*2,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		}
	    &add("esp",4);
	}
	&ret();

	&function_end_B("_x86_DES_encrypt");
	}

sub DES_decrypt_internal()
	{
	&function_begin_B("_x86_DES_decrypt");

	if ($small_footprint)
	    {
	    &push("ecx");
	    &lea("ecx",&DWP(128,"ecx"));
	    &push("ecx");
	    &set_label("dloop");
		&D_ENCRYPT(0,$L,$R,-2,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		&comment("");
		&D_ENCRYPT(1,$R,$L,-4,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		&comment("");
		&sub("ecx",16);
		&cmp("ecx",&swtmp(1));
		&mov(&swtmp(0),"ecx");
		&ja(&label("dloop"));
	    &add("esp",8);
	    }
	else
	    {
	    &push("ecx");
	    for ($i=15; $i>0; $i-=2)
		{
		&comment("Round $i");
		&D_ENCRYPT(15-$i,$L,$R,$i*2,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		&comment("Round ".sprintf("%d",$i-1));
		&D_ENCRYPT(15-$i+1,$R,$L,($i-1)*2,$trans,"eax","ebx","ecx","edx",&swtmp(0));
		}
	    &add("esp",4);
	    }
	&ret();

	&function_end_B("_x86_DES_decrypt");
	}

sub DES_encrypt
	{
	local($name,$do_ip)=@_;

	&function_begin_B($name);

	&push("esi");
	&push("edi");

	&comment("");
	&comment("Load the 2 words");

	if ($do_ip)
		{
		&mov($R,&wparam(0));
		 &xor(	"ecx",		"ecx"		);

		&push("ebx");
		&push("ebp");

		&mov("eax",&DWP(0,$R,"",0));
		 &mov("ebx",&wparam(2));	# get encrypt flag
		&mov($L,&DWP(4,$R,"",0));
		&comment("");
		&comment("IP");
		&IP_new("eax",$L,$R,3);
		}
	else
		{
		&mov("eax",&wparam(0));
		 &xor(	"ecx",		"ecx"		);

		&push("ebx");
		&push("ebp");

		&mov($R,&DWP(0,"eax","",0));
		 &mov("ebx",&wparam(2));	# get encrypt flag
		&rotl($R,3);
		&mov($L,&DWP(4,"eax","",0));
		&rotl($L,3);
		}

	# PIC-ification:-)
	&call	(&label("pic_point"));
	&set_label("pic_point");
	&blindpop($trans);
	&lea	($trans,&DWP(&label("des_sptrans")."-".&label("pic_point"),$trans));

	&mov(	"ecx",	&wparam(1)	);

	&cmp("ebx","0");
	&je(&label("decrypt"));
	&call("_x86_DES_encrypt");
	&jmp(&label("done"));
	&set_label("decrypt");
	&call("_x86_DES_decrypt");
	&set_label("done");

	if ($do_ip)
		{
		&comment("");
		&comment("FP");
		&mov("edx",&wparam(0));
		&FP_new($L,$R,"eax",3);

		&mov(&DWP(0,"edx","",0),"eax");
		&mov(&DWP(4,"edx","",0),$R);
		}
	else
		{
		&comment("");
		&comment("Fixup");
		&rotr($L,3);		# r
		 &mov("eax",&wparam(0));
		&rotr($R,3);		# l
		 &mov(&DWP(0,"eax","",0),$L);
		 &mov(&DWP(4,"eax","",0),$R);
		}

	&pop("ebp");
	&pop("ebx");
	&pop("edi");
	&pop("esi");
	&ret();

	&function_end_B($name);
	}

sub D_ENCRYPT
	{
	local($r,$L,$R,$S,$trans,$u,$tmp1,$tmp2,$t,$wp1)=@_;

	 &mov(	$u,		&DWP(&n2a($S*4),$tmp2,"",0));
	&xor(	$tmp1,		$tmp1);
	 &mov(	$t,		&DWP(&n2a(($S+1)*4),$tmp2,"",0));
	&xor(	$u,		$R);
	&xor(	$tmp2,		$tmp2);
	 &xor(	$t,		$R);
	&and(	$u,		"0xFF"	);
	 &and(	$t,		"0xFF"	);
	&movb(	&LB($tmp1),	&LB($u)	);
	 &movb(	&LB($tmp2),	&HB($u)	);
	&rotr(	$t,		4		);
	&xor(	$L,		&DWP("     ",$trans,$tmp1,0));
	 &movb(	&LB($tmp1),	&LB($t)	);
	 &xor(	$L,		&DWP("0xFF",$trans,$tmp2,0));
	 &movb(	&LB($tmp2),	&HB($t)	);
	&shr(	$u,		16);
	 &xor(	$L,		&DWP("0xFF",$trans,$tmp1,0));
	 &movb(	&LB($tmp1),	&HB($u)	);
	&shr(	$t,		16);
	 &xor(	$L,		&DWP("0xFF",$trans,$tmp2,0));
	&movb(	&LB($tmp2),	&HB($t)	);
	 &and(	$u,		"0xFF"	);
	&and(	$t,		"0xFF"	);
	 &xor(	$L,		&DWP("0xFF",$trans,$tmp1,0));
	 &xor(	$L,		&DWP("0xFF",$trans,$tmp2,0));
	&mov(	$tmp2,		$wp1	);
	 &xor(	$L,		&DWP("0xFF",$trans,$u,0));
	 &xor(	$L,		&DWP("0xFF",$trans,$t,0));
	}

sub n2a
	{
	sprintf("%d",$_[0]);
	}

# now has a side affect of rotating $a by $shift
sub R_PERM_OP
	{
	local($a,$b,$tt,$shift,$mask,$last)=@_;

	&rotl(	$a,		$shift		) if ($shift != 0);
	&mov(	$tt,		$a		);
	&xor(	$a,		$b		);
	&and(	$a,		$mask		);
	# This can never succeed, and besides it is difficult to see what the
	# idea was - Ben 13 Feb 99
	if (!$last eq $b)
		{
		&xor(	$b,		$a		);
		&xor(	$tt,		$a		);
		}
	else
		{
		&xor(	$tt,		$a		);
		&xor(	$b,		$a		);
		}
	&comment("");
	}

sub IP_new
	{
	local($l,$r,$tt,$lr)=@_;

	&R_PERM_OP($l,$r,$tt, 4,"0xFF",$l);
	&R_PERM_OP($r,$tt,$l,20,"0xFF",$l);
	&R_PERM_OP($l,$tt,$r,14,"0xFF",$r);
	&R_PERM_OP($tt,$r,$l,22,"0xFF",$r);
	&R_PERM_OP($l,$r,$tt, 9,"0xFF",$r);

	if ($lr != 3)
		{
		if (($lr-3) < 0)
			{ &rotr($tt,	3-$lr); }
		else	{ &rotl($tt,	$lr-3); }
		}
	if ($lr != 2)
		{
		if (($lr-2) < 0)
			{ &rotr($r,	2-$lr); }
		else	{ &rotl($r,	$lr-2); }
		}
	}

sub FP_new
	{
	local($l,$r,$tt,$lr)=@_;

	if ($lr != 2)
		{
		if (($lr-2) < 0)
			{ &rotl($r,	2-$lr); }
		else	{ &rotr($r,	$lr-2); }
		}
	if ($lr != 3)
		{
		if (($lr-3) < 0)
			{ &rotl($l,	3-$lr); }
		else	{ &rotr($l,	$lr-3); }
		}

	&R_PERM_OP($l,$r,$tt, 0,"0xFF",$r);
	&R_PERM_OP($tt,$r,$l,23,"0xFF",$r);
	&R_PERM_OP($l,$r,$tt,10,"0xFF",$l);
	&R_PERM_OP($r,$tt,$l,18,"0xFF",$l);
	&R_PERM_OP($l,$tt,$r,12,"0xFF",$r);
	&rotr($tt	, 4);
	}

sub DES_SPtrans
	{
	&set_label("DES_SPtrans",64);
	&set_label("des_sptrans");
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 1
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 2
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 3
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 4
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 5
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 6
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	# nibble 7
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	&data_word(0xFF, 0xFF, 0xFF, 0xFF);
	}
