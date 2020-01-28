.text	
















.type	_vpaes_encrypt_core,@function
.align	16
_vpaes_encrypt_core:
.cfi_startproc	
	movq	%rdx,%r9
	movq	$16,%r11
	movl	240(%rdx),%eax
	movdqa	%xmm9,%xmm1
	movdqa	.Lk_ipt(%rip),%xmm2
	pandn	%xmm0,%xmm1
	movdqu	(%r9),%xmm5
	psrld	$4,%xmm1
	pand	%xmm9,%xmm0
.byte	102,15,56,0,208
	movdqa	.Lk_ipt+16(%rip),%xmm0
.byte	102,15,56,0,193
	pxor	%xmm5,%xmm2
	addq	$16,%r9
	pxor	%xmm2,%xmm0
	leaq	.Lk_mc_backward(%rip),%r10
	jmp	.Lenc_entry

.align	16
.Lenc_loop:

	movdqa	%xmm13,%xmm4
	movdqa	%xmm12,%xmm0
.byte	102,15,56,0,226
.byte	102,15,56,0,195
	pxor	%xmm5,%xmm4
	movdqa	%xmm15,%xmm5
	pxor	%xmm4,%xmm0
	movdqa	-64(%r11,%r10,1),%xmm1
.byte	102,15,56,0,234
	movdqa	(%r11,%r10,1),%xmm4
	movdqa	%xmm14,%xmm2
.byte	102,15,56,0,211
	movdqa	%xmm0,%xmm3
	pxor	%xmm5,%xmm2
.byte	102,15,56,0,193
	addq	$16,%r9
	pxor	%xmm2,%xmm0
.byte	102,15,56,0,220
	addq	$16,%r11
	pxor	%xmm0,%xmm3
.byte	102,15,56,0,193
	andq	$0xFF,%r11
	subq	$1,%rax
	pxor	%xmm3,%xmm0

.Lenc_entry:

	movdqa	%xmm9,%xmm1
	movdqa	%xmm11,%xmm5
	pandn	%xmm0,%xmm1
	psrld	$4,%xmm1
	pand	%xmm9,%xmm0
.byte	102,15,56,0,232
	movdqa	%xmm10,%xmm3
	pxor	%xmm1,%xmm0
.byte	102,15,56,0,217
	movdqa	%xmm10,%xmm4
	pxor	%xmm5,%xmm3
.byte	102,15,56,0,224
	movdqa	%xmm10,%xmm2
	pxor	%xmm5,%xmm4
.byte	102,15,56,0,211
	movdqa	%xmm10,%xmm3
	pxor	%xmm0,%xmm2
.byte	102,15,56,0,220
	movdqu	(%r9),%xmm5
	pxor	%xmm1,%xmm3
	jnz	.Lenc_loop


	movdqa	-96(%r10),%xmm4
	movdqa	-80(%r10),%xmm0
.byte	102,15,56,0,226
	pxor	%xmm5,%xmm4
.byte	102,15,56,0,195
	movdqa	64(%r11,%r10,1),%xmm1
	pxor	%xmm4,%xmm0
.byte	102,15,56,0,193
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_encrypt_core,.-_vpaes_encrypt_core






.type	_vpaes_decrypt_core,@function
.align	16
_vpaes_decrypt_core:
.cfi_startproc	
	movq	%rdx,%r9
	movl	240(%rdx),%eax
	movdqa	%xmm9,%xmm1
	movdqa	.Lk_dipt(%rip),%xmm2
	pandn	%xmm0,%xmm1
	movq	%rax,%r11
	psrld	$4,%xmm1
	movdqu	(%r9),%xmm5
	shlq	$4,%r11
	pand	%xmm9,%xmm0
.byte	102,15,56,0,208
	movdqa	.Lk_dipt+16(%rip),%xmm0
	xorq	$0xFF,%r11
	leaq	.Lk_dsbd(%rip),%r10
.byte	102,15,56,0,193
	andq	$0xFF,%r11
	pxor	%xmm5,%xmm2
	movdqa	.Lk_mc_forward+48(%rip),%xmm5
	pxor	%xmm2,%xmm0
	addq	$16,%r9
	addq	%r10,%r11
	jmp	.Ldec_entry

.align	16
.Ldec_loop:



	movdqa	-32(%r10),%xmm4
	movdqa	-16(%r10),%xmm1
.byte	102,15,56,0,226
.byte	102,15,56,0,203
	pxor	%xmm4,%xmm0
	movdqa	0(%r10),%xmm4
	pxor	%xmm1,%xmm0
	movdqa	16(%r10),%xmm1

.byte	102,15,56,0,226
.byte	102,15,56,0,197
.byte	102,15,56,0,203
	pxor	%xmm4,%xmm0
	movdqa	32(%r10),%xmm4
	pxor	%xmm1,%xmm0
	movdqa	48(%r10),%xmm1

.byte	102,15,56,0,226
.byte	102,15,56,0,197
.byte	102,15,56,0,203
	pxor	%xmm4,%xmm0
	movdqa	64(%r10),%xmm4
	pxor	%xmm1,%xmm0
	movdqa	80(%r10),%xmm1

.byte	102,15,56,0,226
.byte	102,15,56,0,197
.byte	102,15,56,0,203
	pxor	%xmm4,%xmm0
	addq	$16,%r9
.byte	102,15,58,15,237,12
	pxor	%xmm1,%xmm0
	subq	$1,%rax

.Ldec_entry:

	movdqa	%xmm9,%xmm1
	pandn	%xmm0,%xmm1
	movdqa	%xmm11,%xmm2
	psrld	$4,%xmm1
	pand	%xmm9,%xmm0
.byte	102,15,56,0,208
	movdqa	%xmm10,%xmm3
	pxor	%xmm1,%xmm0
.byte	102,15,56,0,217
	movdqa	%xmm10,%xmm4
	pxor	%xmm2,%xmm3
.byte	102,15,56,0,224
	pxor	%xmm2,%xmm4
	movdqa	%xmm10,%xmm2
.byte	102,15,56,0,211
	movdqa	%xmm10,%xmm3
	pxor	%xmm0,%xmm2
.byte	102,15,56,0,220
	movdqu	(%r9),%xmm0
	pxor	%xmm1,%xmm3
	jnz	.Ldec_loop


	movdqa	96(%r10),%xmm4
.byte	102,15,56,0,226
	pxor	%xmm0,%xmm4
	movdqa	112(%r10),%xmm0
	movdqa	-352(%r11),%xmm2
.byte	102,15,56,0,195
	pxor	%xmm4,%xmm0
.byte	102,15,56,0,194
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_decrypt_core,.-_vpaes_decrypt_core






.type	_vpaes_schedule_core,@function
.align	16
_vpaes_schedule_core:
.cfi_startproc	





	call	_vpaes_preheat
	movdqa	.Lk_rcon(%rip),%xmm8
	movdqu	(%rdi),%xmm0


	movdqa	%xmm0,%xmm3
	leaq	.Lk_ipt(%rip),%r11
	call	_vpaes_schedule_transform
	movdqa	%xmm0,%xmm7

	leaq	.Lk_sr(%rip),%r10
	testq	%rcx,%rcx
	jnz	.Lschedule_am_decrypting


	movdqu	%xmm0,(%rdx)
	jmp	.Lschedule_go

.Lschedule_am_decrypting:

	movdqa	(%r8,%r10,1),%xmm1
.byte	102,15,56,0,217
	movdqu	%xmm3,(%rdx)
	xorq	$0xFF,%r8

.Lschedule_go:
	cmpl	$192,%esi
	ja	.Lschedule_256
	je	.Lschedule_192










.Lschedule_128:
	movl	$10,%esi

.Loop_schedule_128:
	call	_vpaes_schedule_round
	decq	%rsi
	jz	.Lschedule_mangle_last
	call	_vpaes_schedule_mangle
	jmp	.Loop_schedule_128
















.align	16
.Lschedule_192:
	movdqu	8(%rdi),%xmm0
	call	_vpaes_schedule_transform
	movdqa	%xmm0,%xmm6
	pxor	%xmm4,%xmm4
	movhlps	%xmm4,%xmm6
	movl	$4,%esi

.Loop_schedule_192:
	call	_vpaes_schedule_round
.byte	102,15,58,15,198,8
	call	_vpaes_schedule_mangle
	call	_vpaes_schedule_192_smear
	call	_vpaes_schedule_mangle
	call	_vpaes_schedule_round
	decq	%rsi
	jz	.Lschedule_mangle_last
	call	_vpaes_schedule_mangle
	call	_vpaes_schedule_192_smear
	jmp	.Loop_schedule_192











.align	16
.Lschedule_256:
	movdqu	16(%rdi),%xmm0
	call	_vpaes_schedule_transform
	movl	$7,%esi

.Loop_schedule_256:
	call	_vpaes_schedule_mangle
	movdqa	%xmm0,%xmm6


	call	_vpaes_schedule_round
	decq	%rsi
	jz	.Lschedule_mangle_last
	call	_vpaes_schedule_mangle


	pshufd	$0xFF,%xmm0,%xmm0
	movdqa	%xmm7,%xmm5
	movdqa	%xmm6,%xmm7
	call	_vpaes_schedule_low_round
	movdqa	%xmm5,%xmm7

	jmp	.Loop_schedule_256












.align	16
.Lschedule_mangle_last:

	leaq	.Lk_deskew(%rip),%r11
	testq	%rcx,%rcx
	jnz	.Lschedule_mangle_last_dec


	movdqa	(%r8,%r10,1),%xmm1
.byte	102,15,56,0,193
	leaq	.Lk_opt(%rip),%r11
	addq	$32,%rdx

.Lschedule_mangle_last_dec:
	addq	$-16,%rdx
	pxor	.Lk_s63(%rip),%xmm0
	call	_vpaes_schedule_transform
	movdqu	%xmm0,(%rdx)


	pxor	%xmm0,%xmm0
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_schedule_core,.-_vpaes_schedule_core















.type	_vpaes_schedule_192_smear,@function
.align	16
_vpaes_schedule_192_smear:
.cfi_startproc	
	pshufd	$0xFF,%xmm6,%xmm1
	pshufd	$0xFF,%xmm7,%xmm0
	pxor	%xmm1,%xmm6
	pxor	%xmm1,%xmm1
	pxor	%xmm0,%xmm6
	movdqa	%xmm6,%xmm0
	movhlps	%xmm1,%xmm6
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_schedule_192_smear,.-_vpaes_schedule_192_smear



















.type	_vpaes_schedule_round,@function
.align	16
_vpaes_schedule_round:
.cfi_startproc	

	pxor	%xmm1,%xmm1
.byte	102,65,15,58,15,200,15
.byte	102,69,15,58,15,192,15
	pxor	%xmm1,%xmm7


	pshufd	$0xFF,%xmm0,%xmm0
.byte	102,15,58,15,192,1




_vpaes_schedule_low_round:

	movdqa	%xmm7,%xmm1
	pslldq	$4,%xmm7
	pxor	%xmm1,%xmm7
	movdqa	%xmm7,%xmm1
	pslldq	$8,%xmm7
	pxor	%xmm1,%xmm7
	pxor	.Lk_s63(%rip),%xmm7


	movdqa	%xmm9,%xmm1
	pandn	%xmm0,%xmm1
	psrld	$4,%xmm1
	pand	%xmm9,%xmm0
	movdqa	%xmm11,%xmm2
.byte	102,15,56,0,208
	pxor	%xmm1,%xmm0
	movdqa	%xmm10,%xmm3
.byte	102,15,56,0,217
	pxor	%xmm2,%xmm3
	movdqa	%xmm10,%xmm4
.byte	102,15,56,0,224
	pxor	%xmm2,%xmm4
	movdqa	%xmm10,%xmm2
.byte	102,15,56,0,211
	pxor	%xmm0,%xmm2
	movdqa	%xmm10,%xmm3
.byte	102,15,56,0,220
	pxor	%xmm1,%xmm3
	movdqa	%xmm13,%xmm4
.byte	102,15,56,0,226
	movdqa	%xmm12,%xmm0
.byte	102,15,56,0,195
	pxor	%xmm4,%xmm0


	pxor	%xmm7,%xmm0
	movdqa	%xmm0,%xmm7
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_schedule_round,.-_vpaes_schedule_round










.type	_vpaes_schedule_transform,@function
.align	16
_vpaes_schedule_transform:
.cfi_startproc	
	movdqa	%xmm9,%xmm1
	pandn	%xmm0,%xmm1
	psrld	$4,%xmm1
	pand	%xmm9,%xmm0
	movdqa	(%r11),%xmm2
.byte	102,15,56,0,208
	movdqa	16(%r11),%xmm0
.byte	102,15,56,0,193
	pxor	%xmm2,%xmm0
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_schedule_transform,.-_vpaes_schedule_transform
























.type	_vpaes_schedule_mangle,@function
.align	16
_vpaes_schedule_mangle:
.cfi_startproc	
	movdqa	%xmm0,%xmm4
	movdqa	.Lk_mc_forward(%rip),%xmm5
	testq	%rcx,%rcx
	jnz	.Lschedule_mangle_dec


	addq	$16,%rdx
	pxor	.Lk_s63(%rip),%xmm4
.byte	102,15,56,0,229
	movdqa	%xmm4,%xmm3
.byte	102,15,56,0,229
	pxor	%xmm4,%xmm3
.byte	102,15,56,0,229
	pxor	%xmm4,%xmm3

	jmp	.Lschedule_mangle_both
.align	16
.Lschedule_mangle_dec:

	leaq	.Lk_dksd(%rip),%r11
	movdqa	%xmm9,%xmm1
	pandn	%xmm4,%xmm1
	psrld	$4,%xmm1
	pand	%xmm9,%xmm4

	movdqa	0(%r11),%xmm2
.byte	102,15,56,0,212
	movdqa	16(%r11),%xmm3
.byte	102,15,56,0,217
	pxor	%xmm2,%xmm3
.byte	102,15,56,0,221

	movdqa	32(%r11),%xmm2
.byte	102,15,56,0,212
	pxor	%xmm3,%xmm2
	movdqa	48(%r11),%xmm3
.byte	102,15,56,0,217
	pxor	%xmm2,%xmm3
.byte	102,15,56,0,221

	movdqa	64(%r11),%xmm2
.byte	102,15,56,0,212
	pxor	%xmm3,%xmm2
	movdqa	80(%r11),%xmm3
.byte	102,15,56,0,217
	pxor	%xmm2,%xmm3
.byte	102,15,56,0,221

	movdqa	96(%r11),%xmm2
.byte	102,15,56,0,212
	pxor	%xmm3,%xmm2
	movdqa	112(%r11),%xmm3
.byte	102,15,56,0,217
	pxor	%xmm2,%xmm3

	addq	$-16,%rdx

.Lschedule_mangle_both:
	movdqa	(%r8,%r10,1),%xmm1
.byte	102,15,56,0,217
	addq	$-16,%r8
	andq	$0xFF,%r8
	movdqu	%xmm3,(%rdx)
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_schedule_mangle,.-_vpaes_schedule_mangle




.globl	vpaes_set_encrypt_key
.type	vpaes_set_encrypt_key,@function
.align	16
vpaes_set_encrypt_key:
.cfi_startproc	
	movl	%esi,%eax
	shrl	$5,%eax
	addl	$5,%eax
	movl	%eax,240(%rdx)

	movl	$0,%ecx
	movl	$0xFF,%r8d
	call	_vpaes_schedule_core
	xorl	%eax,%eax
	.byte	0xFF,0xFF
.cfi_endproc	
.size	vpaes_set_encrypt_key,.-vpaes_set_encrypt_key

.globl	vpaes_set_decrypt_key
.type	vpaes_set_decrypt_key,@function
.align	16
vpaes_set_decrypt_key:
.cfi_startproc	
	movl	%esi,%eax
	shrl	$5,%eax
	addl	$5,%eax
	movl	%eax,240(%rdx)
	shll	$4,%eax
	leaq	16(%rdx,%rax,1),%rdx

	movl	$1,%ecx
	movl	%esi,%r8d
	shrl	$1,%r8d
	andl	$32,%r8d
	xorl	$32,%r8d
	call	_vpaes_schedule_core
	xorl	%eax,%eax
	.byte	0xFF,0xFF
.cfi_endproc	
.size	vpaes_set_decrypt_key,.-vpaes_set_decrypt_key

.globl	vpaes_encrypt
.type	vpaes_encrypt,@function
.align	16
vpaes_encrypt:
.cfi_startproc	
	movdqu	(%rdi),%xmm0
	call	_vpaes_preheat
	call	_vpaes_encrypt_core
	movdqu	%xmm0,(%rsi)
	.byte	0xFF,0xFF
.cfi_endproc	
.size	vpaes_encrypt,.-vpaes_encrypt

.globl	vpaes_decrypt
.type	vpaes_decrypt,@function
.align	16
vpaes_decrypt:
.cfi_startproc	
	movdqu	(%rdi),%xmm0
	call	_vpaes_preheat
	call	_vpaes_decrypt_core
	movdqu	%xmm0,(%rsi)
	.byte	0xFF,0xFF
.cfi_endproc	
.size	vpaes_decrypt,.-vpaes_decrypt
.globl	vpaes_cbc_encrypt
.type	vpaes_cbc_encrypt,@function
.align	16
vpaes_cbc_encrypt:
.cfi_startproc	
	xchgq	%rcx,%rdx
	subq	$16,%rcx
	jc	.Lcbc_abort
	movdqu	(%r8),%xmm6
	subq	%rdi,%rsi
	call	_vpaes_preheat
	cmpl	$0,%r9d
	je	.Lcbc_dec_loop
	jmp	.Lcbc_enc_loop
.align	16
.Lcbc_enc_loop:
	movdqu	(%rdi),%xmm0
	pxor	%xmm6,%xmm0
	call	_vpaes_encrypt_core
	movdqa	%xmm0,%xmm6
	movdqu	%xmm0,(%rsi,%rdi,1)
	leaq	16(%rdi),%rdi
	subq	$16,%rcx
	jnc	.Lcbc_enc_loop
	jmp	.Lcbc_done
.align	16
.Lcbc_dec_loop:
	movdqu	(%rdi),%xmm0
	movdqa	%xmm0,%xmm7
	call	_vpaes_decrypt_core
	pxor	%xmm6,%xmm0
	movdqa	%xmm7,%xmm6
	movdqu	%xmm0,(%rsi,%rdi,1)
	leaq	16(%rdi),%rdi
	subq	$16,%rcx
	jnc	.Lcbc_dec_loop
.Lcbc_done:
	movdqu	%xmm6,(%r8)
.Lcbc_abort:
	.byte	0xFF,0xFF
.cfi_endproc	
.size	vpaes_cbc_encrypt,.-vpaes_cbc_encrypt






.type	_vpaes_preheat,@function
.align	16
_vpaes_preheat:
.cfi_startproc	
	leaq	.Lk_s0F(%rip),%r10
	movdqa	-32(%r10),%xmm10
	movdqa	-16(%r10),%xmm11
	movdqa	0(%r10),%xmm9
	movdqa	48(%r10),%xmm13
	movdqa	64(%r10),%xmm12
	movdqa	80(%r10),%xmm15
	movdqa	96(%r10),%xmm14
	.byte	0xFF,0xFF
.cfi_endproc	
.size	_vpaes_preheat,.-_vpaes_preheat





.type	_vpaes_consts,@object
.align	64
_vpaes_consts:
.Lk_inv:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_s0F:
.quad	0xFF, 0xFF

.Lk_ipt:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_sb1:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_sb2:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_sbo:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_mc_forward:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_mc_backward:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_sr:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_rcon:
.quad	0xFF, 0xFF

.Lk_s63:
.quad	0xFF, 0xFF

.Lk_opt:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_deskew:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF





.Lk_dksd:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dksb:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dkse:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dks9:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF





.Lk_dipt:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF

.Lk_dsb9:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dsbd:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dsbb:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dsbe:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.Lk_dsbo:
.quad	0xFF, 0xFF
.quad	0xFF, 0xFF
.byte	86,101,99,116,111,114,32,80,101,114,109,117,116,97,116,105,111,110,32,65,69,83,32,102,111,114,32,120,56,54,95,54,52,47,83,83,83,69,51,44,32,77,105,107,101,32,72,97,109,98,117,114,103,32,40,83,116,97,110,102,111,114,100,32,85,110,105,118,101,114,115,105,116,121,41,0
.align	64
.size	_vpaes_consts,.-_vpaes_consts
