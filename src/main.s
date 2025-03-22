	.file	"main.c"
	.text
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"packet too large! discarded\n"
	.text
	.p2align 4
	.globl	packet_handler
	.type	packet_handler, @function
packet_handler:
.LFB28:
	.cfi_startproc
	pushq	%r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	movq	%rdx, %r12
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	leaq	16640016+ring_buffer(%rip), %rbp
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	movq	%rbp, %rdi
	movq	%rsi, %rbx
	call	pthread_mutex_lock@PLT
	cmpl	$10000, 16640008+ring_buffer(%rip)
	jne	.L2
	movl	16640004+ring_buffer(%rip), %eax
	movl	$3518437209, %ecx
	movl	$9999, 16640008+ring_buffer(%rip)
	addl	$1, %eax
	movq	%rax, %rdx
	imulq	%rcx, %rax
	shrq	$45, %rax
	imull	$10000, %eax, %eax
	subl	%eax, %edx
	movl	%edx, 16640004+ring_buffer(%rip)
.L2:
	movl	20(%rbx), %r8d
	movl	16640000+ring_buffer(%rip), %eax
	leaq	ring_buffer(%rip), %rdx
	cmpl	$1518, %r8d
	ja	.L20
	leaq	(%rax,%rax,2), %rcx
	leaq	(%rax,%rcx,4), %r9
	salq	$7, %r9
	leaq	(%rdx,%r9), %rdi
	cmpl	$8, %r8d
	jnb	.L21
	xorl	%ecx, %ecx
	testb	$4, %r8b
	jne	.L22
.L5:
	testb	$2, %r8b
	jne	.L23
.L6:
	andl	$1, %r8d
	jne	.L24
.L7:
	movdqu	(%rbx), %xmm0
	leaq	1520(%rdx,%r9), %rcx
	leaq	16640104+ring_buffer(%rip), %rdi
	movaps	%xmm0, (%rcx)
	movq	16(%rbx), %rsi
	movq	%rsi, 16(%rcx)
	leaq	(%rax,%rax,2), %rcx
	leaq	(%rax,%rcx,4), %rax
	movl	$3518437209, %ecx
	salq	$7, %rax
	addq	%rax, %rdx
	movl	20(%rbx), %eax
	movl	%eax, 1544(%rdx)
	movl	16640000+ring_buffer(%rip), %eax
	movdqu	(%rbx), %xmm1
	addl	$1, 16640008+ring_buffer(%rip)
	addl	$1, %eax
	movaps	%xmm1, 1552(%rdx)
	movq	%rax, %rdx
	imulq	%rcx, %rax
	shrq	$45, %rax
	imull	$10000, %eax, %eax
	subl	%eax, %edx
	movl	%edx, 16640000+ring_buffer(%rip)
	call	pthread_cond_signal@PLT
	popq	%rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 24
	movq	%rbp, %rdi
	popq	%rbp
	.cfi_def_cfa_offset 16
	popq	%r12
	.cfi_def_cfa_offset 8
	jmp	pthread_mutex_unlock@PLT
	.p2align 4,,10
	.p2align 3
.L24:
	.cfi_restore_state
	movzbl	(%r12,%rcx), %esi
	movb	%sil, (%rdi,%rcx)
	jmp	.L7
	.p2align 4,,10
	.p2align 3
.L23:
	movzwl	(%r12,%rcx), %r10d
	movw	%r10w, (%rdi,%rcx)
	addq	$2, %rcx
	andl	$1, %r8d
	je	.L7
	jmp	.L24
	.p2align 4,,10
	.p2align 3
.L22:
	movl	(%r12), %ecx
	movl	%ecx, (%rdi)
	movl	$4, %ecx
	testb	$2, %r8b
	je	.L6
	jmp	.L23
	.p2align 4,,10
	.p2align 3
.L21:
	movl	%r8d, %ecx
	movq	%r12, %rsi
	shrl	$3, %ecx
	rep movsq
	xorl	%ecx, %ecx
	movq	%rsi, %r12
	testb	$4, %r8b
	je	.L5
	jmp	.L22
	.p2align 4,,10
	.p2align 3
.L20:
	movq	stderr(%rip), %rcx
	movl	$28, %edx
	movl	$1, %esi
	leaq	.LC0(%rip), %rdi
	call	fwrite@PLT
	popq	%rbx
	.cfi_def_cfa_offset 24
	movq	%rbp, %rdi
	popq	%rbp
	.cfi_def_cfa_offset 16
	popq	%r12
	.cfi_def_cfa_offset 8
	jmp	pthread_mutex_unlock@PLT
	.cfi_endproc
.LFE28:
	.size	packet_handler, .-packet_handler
	.section	.rodata.str1.1
.LC1:
	.string	"Couldn find devices %s\n"
.LC2:
	.string	"No devices found\n"
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align 8
.LC3:
	.string	"can't get netmask for device %s: %s\n"
	.section	.rodata.str1.1
.LC4:
	.string	"couldn't open device %s: %s\n"
	.section	.rodata.str1.8
	.align 8
.LC5:
	.string	"Device %s doesn't provide ethenet header\n"
	.align 8
.LC6:
	.string	"Couldn't parse filter %s : %s\n"
	.align 8
.LC7:
	.string	"Couldn't installl filter %s: %s\n"
	.section	.rodata.str1.1
.LC8:
	.string	"Error in loop %s\n"
	.text
	.p2align 4
	.globl	capture_packets
	.type	capture_packets, @function
capture_packets:
.LFB33:
	.cfi_startproc
	pushq	%r13
	.cfi_def_cfa_offset 16
	.cfi_offset 13, -16
	pushq	%r12
	.cfi_def_cfa_offset 24
	.cfi_offset 12, -24
	movq	%rdi, %r12
	pushq	%rbp
	.cfi_def_cfa_offset 32
	.cfi_offset 6, -32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	.cfi_offset 3, -40
	subq	$296, %rsp
	.cfi_def_cfa_offset 336
	leaq	32(%rsp), %rbp
	leaq	8(%rsp), %rdi
	movq	%rbp, %rsi
	call	pcap_findalldevs@PLT
	cmpl	$-1, %eax
	je	.L37
	movq	8(%rsp), %rax
	testq	%rax, %rax
	je	.L38
	movq	8(%rax), %r13
	movq	%rsp, %rdx
	leaq	4(%rsp), %rsi
	movq	%rbp, %rcx
	movq	%r13, %rdi
	call	pcap_lookupnet@PLT
	cmpl	$-1, %eax
	je	.L39
.L28:
	movq	%rbp, %r8
	movl	$1000, %ecx
	movl	$1, %edx
	movq	%r13, %rdi
	movl	$8192, %esi
	call	pcap_open_live@PLT
	movq	%rax, %rbx
	testq	%rax, %rax
	je	.L40
	movq	%rax, %rdi
	call	pcap_datalink@PLT
	cmpl	$1, %eax
	jne	.L41
	leaq	16(%rsp), %rbp
	movl	4(%rsp), %r8d
	xorl	%ecx, %ecx
	movq	%r12, %rdx
	movq	%rbp, %rsi
	movq	%rbx, %rdi
	call	pcap_compile@PLT
	cmpl	$-1, %eax
	je	.L42
	movq	%rbp, %rsi
	movq	%rbx, %rdi
	call	pcap_setfilter@PLT
	cmpl	$-1, %eax
	je	.L43
	xorl	%ecx, %ecx
	leaq	packet_handler(%rip), %rdx
	movl	$10000, %esi
	movq	%rbx, %rdi
	call	pcap_loop@PLT
	cmpl	$-1, %eax
	je	.L44
.L33:
	leaq	16640016+ring_buffer(%rip), %r12
	movq	%r12, %rdi
	call	pthread_mutex_lock@PLT
	movl	$1, %eax
	xchgb	16640012+ring_buffer(%rip), %al
	leaq	88(%r12), %rdi
	call	pthread_cond_signal@PLT
	movq	%r12, %rdi
	call	pthread_mutex_unlock@PLT
	movq	8(%rsp), %rdi
	call	pcap_freealldevs@PLT
	movq	%rbp, %rdi
	call	pcap_freecode@PLT
	movq	%rbx, %rdi
	call	pcap_close@PLT
	addq	$296, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 40
	xorl	%eax, %eax
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%rbp
	.cfi_def_cfa_offset 24
	popq	%r12
	.cfi_def_cfa_offset 16
	popq	%r13
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L39:
	.cfi_restore_state
	movq	stderr(%rip), %rdi
	movq	%rbp, %rcx
	movq	%r13, %rdx
	xorl	%eax, %eax
	leaq	.LC3(%rip), %rsi
	call	fprintf@PLT
	movl	$0, 4(%rsp)
	movl	$0, (%rsp)
	jmp	.L28
	.p2align 4,,10
	.p2align 3
.L44:
	movq	%rbx, %rdi
	call	pcap_geterr@PLT
	movq	stderr(%rip), %rdi
	leaq	.LC8(%rip), %rsi
	movq	%rax, %rdx
	xorl	%eax, %eax
	call	fprintf@PLT
	jmp	.L33
.L38:
	movq	stderr(%rip), %rcx
	movl	$17, %edx
	movl	$1, %esi
	leaq	.LC2(%rip), %rdi
	call	fwrite@PLT
	movq	8(%rsp), %rdi
	call	pcap_freealldevs@PLT
	movl	$1, %edi
	call	exit@PLT
.L37:
	movq	stderr(%rip), %rdi
	movq	%rbp, %rdx
	leaq	.LC1(%rip), %rsi
	xorl	%eax, %eax
	call	fprintf@PLT
	movl	$1, %edi
	call	exit@PLT
.L43:
	movq	%rbx, %rdi
	call	pcap_geterr@PLT
	movq	%r12, %rdx
	leaq	.LC7(%rip), %rsi
	movq	%rax, %rcx
.L36:
	movq	stderr(%rip), %rdi
	xorl	%eax, %eax
	call	fprintf@PLT
	movq	%rbp, %rdi
	call	pcap_freecode@PLT
.L35:
	movq	%rbx, %rdi
	call	pcap_close@PLT
	movq	8(%rsp), %rdi
	call	pcap_freealldevs@PLT
	movl	$1, %edi
	call	exit@PLT
.L42:
	movq	%rbx, %rdi
	call	pcap_geterr@PLT
	movq	%r12, %rdx
	leaq	.LC6(%rip), %rsi
	movq	%rax, %rcx
	jmp	.L36
.L41:
	movq	stderr(%rip), %rdi
	movq	%r13, %rdx
	leaq	.LC5(%rip), %rsi
	xorl	%eax, %eax
	call	fprintf@PLT
	jmp	.L35
.L40:
	movq	stderr(%rip), %rdi
	movq	%rbp, %rcx
	movq	%r13, %rdx
	xorl	%eax, %eax
	leaq	.LC4(%rip), %rsi
	call	fprintf@PLT
	movq	8(%rsp), %rdi
	call	pcap_freealldevs@PLT
	movl	$1, %edi
	call	exit@PLT
	.cfi_endproc
.LFE33:
	.size	capture_packets, .-capture_packets
	.section	.rodata.str1.1
.LC9:
	.string	"%08X "
.LC10:
	.string	"%02X "
.LC11:
	.string	"   "
.LC12:
	.string	"| "
.LC13:
	.string	"%s"
	.text
	.p2align 4
	.type	print_hex_ascii_line.part.0, @function
print_hex_ascii_line.part.0:
.LFB36:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$104, %rsp
	.cfi_def_cfa_offset 160
	movq	%rdi, (%rsp)
	testl	%esi, %esi
	jle	.L45
	movl	%esi, 8(%rsp)
	leaq	16(%rsp), %r12
	movl	%edx, 12(%rsp)
	.p2align 4,,10
	.p2align 3
.L46:
	movl	8(%rsp), %eax
	movl	$16, %ebp
	movl	12(%rsp), %ecx
	movq	%r12, %rdi
	leaq	.LC9(%rip), %rdx
	movl	$80, %esi
	movl	$9, %r15d
	movl	$80, %r13d
	cmpl	%ebp, %eax
	cmovle	%eax, %ebp
	xorl	%eax, %eax
	xorl	%r14d, %r14d
	call	snprintf@PLT
	jmp	.L50
	.p2align 4,,10
	.p2align 3
.L71:
	movq	(%rsp), %rax
	leaq	.LC10(%rip), %rdx
	movzbl	(%rax,%r14), %ecx
	xorl	%eax, %eax
	call	snprintf@PLT
	addl	%eax, %r15d
.L48:
	cmpl	$7, %ebx
	jne	.L49
	cmpl	$79, %r15d
	ja	.L49
	movslq	%r15d, %rax
	addl	$1, %r15d
	movb	$32, 16(%rsp,%rax)
.L49:
	addq	$1, %r14
	cmpq	$16, %r14
	je	.L70
.L50:
	movslq	%r15d, %rdi
	movq	%r13, %rsi
	movl	%r14d, %ebx
	subq	%rdi, %rsi
	addq	%r12, %rdi
	cmpl	%r14d, %ebp
	jg	.L71
	leaq	.LC11(%rip), %rdx
	xorl	%eax, %eax
	call	snprintf@PLT
	addl	%eax, %r15d
	jmp	.L48
	.p2align 4,,10
	.p2align 3
.L70:
	movslq	%r15d, %rdi
	movl	$80, %esi
	xorl	%eax, %eax
	movslq	%ebp, %r14
	subq	%rdi, %rsi
	leaq	.LC12(%rip), %rdx
	addq	%r12, %rdi
	call	snprintf@PLT
	leal	(%rax,%r15), %r13d
	movq	(%rsp), %rax
	movq	%rax, %rbx
	leaq	(%rax,%r14), %r15
	.p2align 4,,10
	.p2align 3
.L53:
	movl	%r13d, %eax
	cmpl	$78, %r13d
	ja	.L51
	call	__ctype_b_loc@PLT
	movzbl	(%rbx), %ecx
	movq	%rax, %rdx
	movq	(%rdx), %rdx
	movq	%rcx, %rax
	testb	$64, 1(%rdx,%rcx,2)
	movl	$46, %ecx
	movslq	%r13d, %rdx
	cmove	%ecx, %eax
	addl	$1, %r13d
	movb	%al, 16(%rsp,%rdx)
	movl	%r13d, %eax
.L51:
	addq	$1, %rbx
	cmpq	%r15, %rbx
	jne	.L53
	cmpl	$78, %eax
	ja	.L54
	movslq	%r13d, %rdx
	leal	1(%r13), %eax
	movb	$10, 16(%rsp,%rdx)
.L55:
	cltq
	movb	$0, 16(%rsp,%rax)
.L56:
	movq	%r12, %rsi
	leaq	.LC13(%rip), %rdi
	xorl	%eax, %eax
	call	printf@PLT
	subl	%ebp, 8(%rsp)
	movl	8(%rsp), %eax
	addq	%r14, (%rsp)
	addl	%ebp, 12(%rsp)
	testl	%eax, %eax
	jg	.L46
.L45:
	addq	$104, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L54:
	.cfi_restore_state
	cmpl	$79, %eax
	jne	.L56
	jmp	.L55
	.cfi_endproc
.LFE36:
	.size	print_hex_ascii_line.part.0, .-print_hex_ascii_line.part.0
	.p2align 4
	.globl	is_rb_full
	.type	is_rb_full, @function
is_rb_full:
.LFB26:
	.cfi_startproc
	xorl	%eax, %eax
	cmpl	$10000, 16640008+ring_buffer(%rip)
	sete	%al
	ret
	.cfi_endproc
.LFE26:
	.size	is_rb_full, .-is_rb_full
	.p2align 4
	.globl	is_rb_empty
	.type	is_rb_empty, @function
is_rb_empty:
.LFB27:
	.cfi_startproc
	movl	16640008+ring_buffer(%rip), %edx
	xorl	%eax, %eax
	testl	%edx, %edx
	sete	%al
	ret
	.cfi_endproc
.LFE27:
	.size	is_rb_empty, .-is_rb_empty
	.section	.rodata.str1.1
.LC14:
	.string	"%02x"
	.text
	.p2align 4
	.globl	print_compiled_filter
	.type	print_compiled_filter, @function
print_compiled_filter:
.LFB29:
	.cfi_startproc
	testl	%edi, %edi
	je	.L85
	pushq	%r13
	.cfi_def_cfa_offset 16
	.cfi_offset 13, -16
	movl	%edi, %r13d
	pushq	%r12
	.cfi_def_cfa_offset 24
	.cfi_offset 12, -24
	leaq	.LC14(%rip), %r12
	pushq	%rbp
	.cfi_def_cfa_offset 32
	.cfi_offset 6, -32
	movq	%rsi, %rbp
	pushq	%rbx
	.cfi_def_cfa_offset 40
	.cfi_offset 3, -40
	movl	$1, %ebx
	subq	$8, %rsp
	.cfi_def_cfa_offset 48
	jmp	.L77
	.p2align 4,,10
	.p2align 3
.L76:
	leaq	1(%rbx), %rax
	cmpq	%rbx, %r13
	je	.L86
.L79:
	movq	%rax, %rbx
.L77:
	movzbl	-1(%rbp,%rbx), %esi
	xorl	%eax, %eax
	movq	%r12, %rdi
	call	printf@PLT
	testb	$7, %bl
	jne	.L76
	movl	$10, %edi
	call	putchar@PLT
	leaq	1(%rbx), %rax
	cmpq	%rbx, %r13
	jne	.L79
.L86:
	addq	$8, %rsp
	.cfi_def_cfa_offset 40
	movl	$10, %edi
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 32
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 24
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 16
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 8
	jmp	putchar@PLT
	.p2align 4,,10
	.p2align 3
.L85:
	movl	$10, %edi
	jmp	putchar@PLT
	.cfi_endproc
.LFE29:
	.size	print_compiled_filter, .-print_compiled_filter
	.p2align 4
	.globl	print_hex_ascii_line
	.type	print_hex_ascii_line, @function
print_hex_ascii_line:
.LFB30:
	.cfi_startproc
	testl	%esi, %esi
	js	.L87
	jmp	print_hex_ascii_line.part.0
.L87:
	ret
	.cfi_endproc
.LFE30:
	.size	print_hex_ascii_line, .-print_hex_ascii_line
	.p2align 4
	.globl	print_payload
	.type	print_payload, @function
print_payload:
.LFB31:
	.cfi_startproc
	testl	%esi, %esi
	js	.L89
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	movq	%rdi, %r15
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	movl	%esi, %r13d
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$8, %rsp
	.cfi_def_cfa_offset 64
	cmpl	$16, %esi
	jle	.L98
	leal	-17(%rsi), %r14d
	movq	%rdi, %rbp
	xorl	%ebx, %ebx
	movl	%r14d, %r12d
	andl	$-16, %r12d
	addl	$16, %r12d
	.p2align 4,,10
	.p2align 3
.L92:
	movl	%ebx, %edx
	movq	%rbp, %rdi
	movl	$16, %esi
	addl	$16, %ebx
	call	print_hex_ascii_line.part.0
	addq	$16, %rbp
	cmpl	%r12d, %ebx
	jne	.L92
	shrl	$4, %r14d
	leal	1(%r14), %eax
	negl	%r14d
	movl	%eax, %edx
	sall	$4, %r14d
	salq	$4, %rax
	sall	$4, %edx
	leal	-16(%r13,%r14), %esi
	leaq	(%r15,%rax), %rdi
.L97:
	addq	$8, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_restore 14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_restore 15
	.cfi_def_cfa_offset 8
	jmp	print_hex_ascii_line.part.0
	.p2align 4,,10
	.p2align 3
.L89:
	ret
	.p2align 4,,10
	.p2align 3
.L98:
	.cfi_def_cfa_offset 64
	.cfi_offset 3, -56
	.cfi_offset 6, -48
	.cfi_offset 12, -40
	.cfi_offset 13, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	xorl	%edx, %edx
	jmp	.L97
	.cfi_endproc
.LFE31:
	.size	print_payload, .-print_payload
	.section	.rodata.str1.1
.LC15:
	.string	"Error: Null packet pointer"
.LC16:
	.string	"packet_t number: %d\n"
	.section	.rodata.str1.8
	.align 8
.LC17:
	.string	"packet_t too small for Ethernet header"
	.align 8
.LC18:
	.string	"packet_t too small for IP header"
	.align 8
.LC19:
	.string	"Invalid IP header length: %u bytes\n"
	.section	.rodata.str1.1
.LC20:
	.string	"From: %s\n"
.LC21:
	.string	"To: %s\n"
.LC22:
	.string	"Protocol: TCP"
	.section	.rodata.str1.8
	.align 8
.LC23:
	.string	"packet_t too small for TCP header"
	.align 8
.LC24:
	.string	"Invalid TCP header length: %u bytes\n"
	.section	.rodata.str1.1
.LC25:
	.string	"Protocol: UDP"
	.section	.rodata.str1.8
	.align 8
.LC26:
	.string	"packet_t too small for UDP header"
	.section	.rodata.str1.1
.LC27:
	.string	"Source port: %u\n"
.LC28:
	.string	"Destination port: %u\n"
.LC29:
	.string	"UDP length: %u\n"
.LC30:
	.string	"UDP checksum: 0x%04x\n"
.LC31:
	.string	"invalid udp length field"
.LC32:
	.string	"Protocol: ICMP"
	.section	.rodata.str1.8
	.align 8
.LC33:
	.string	"packet_t too small for ICMP header"
	.section	.rodata.str1.1
.LC34:
	.string	"ICMP type: %u\n"
.LC35:
	.string	"ICMP Code: %u\n"
.LC36:
	.string	"ICMP Checksum: 0x%04x\n"
.LC37:
	.string	"Protocol: Unknown"
.LC38:
	.string	"Payload size %d bytes\n"
	.text
	.p2align 4
	.globl	process_packet
	.type	process_packet, @function
process_packet:
.LFB32:
	.cfi_startproc
	testq	%rdi, %rdi
	je	.L122
	pushq	%r14
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
	xorl	%eax, %eax
	pushq	%r13
	.cfi_def_cfa_offset 24
	.cfi_offset 13, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset 12, -32
	pushq	%rbp
	.cfi_def_cfa_offset 40
	.cfi_offset 6, -40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset 3, -48
	movq	%rdi, %rbx
	leaq	.LC16(%rip), %rdi
	subq	$64, %rsp
	.cfi_def_cfa_offset 112
	movl	count.0(%rip), %esi
	call	printf@PLT
	movl	1544(%rbx), %eax
	addl	$1, count.0(%rip)
	leaq	.LC17(%rip), %rdi
	cmpl	$13, %eax
	jle	.L120
	cmpl	$33, %eax
	jle	.L123
	movzbl	14(%rbx), %ebp
	movl	30(%rbx), %edx
	movdqu	14(%rbx), %xmm0
	andl	$15, %ebp
	movl	%edx, 16(%rsp)
	sall	$2, %ebp
	movaps	%xmm0, (%rsp)
	leal	-20(%rbp), %edx
	cmpl	$40, %edx
	ja	.L103
	leal	13(%rbp), %edx
	cmpl	%edx, %eax
	jg	.L104
.L103:
	movl	%ebp, %esi
	leaq	.LC19(%rip), %rdi
.L121:
	addq	$64, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 48
	xorl	%eax, %eax
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 24
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_restore 14
	.cfi_def_cfa_offset 8
	jmp	printf@PLT
	.p2align 4,,10
	.p2align 3
.L123:
	.cfi_restore_state
	leaq	.LC18(%rip), %rdi
.L120:
	addq	$64, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 24
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_restore 14
	.cfi_def_cfa_offset 8
	jmp	puts@PLT
	.p2align 4,,10
	.p2align 3
.L104:
	.cfi_restore_state
	movl	12(%rsp), %edi
	call	inet_ntoa@PLT
	leaq	.LC20(%rip), %rdi
	movq	%rax, %rsi
	xorl	%eax, %eax
	call	printf@PLT
	movl	16(%rsp), %edi
	call	inet_ntoa@PLT
	leaq	.LC21(%rip), %rdi
	movq	%rax, %rsi
	xorl	%eax, %eax
	call	printf@PLT
	movzbl	9(%rsp), %eax
	cmpb	$6, %al
	je	.L105
	cmpb	$17, %al
	je	.L106
	leaq	.LC37(%rip), %rdi
	cmpb	$1, %al
	jne	.L120
	leaq	.LC32(%rip), %rdi
	call	puts@PLT
	movslq	%ebp, %rax
	movslq	1544(%rbx), %rdx
	leaq	.LC33(%rip), %rdi
	leaq	22(%rax), %r13
	cmpq	%r13, %rdx
	jb	.L120
	movq	14(%rbx,%rax), %r12
	leaq	.LC34(%rip), %rdi
	xorl	%eax, %eax
	addl	$8, %ebp
	addq	%rbx, %r13
	movzbl	%r12b, %esi
	call	printf@PLT
	movl	%r12d, %eax
	shrl	$16, %r12d
	leaq	.LC35(%rip), %rdi
	movzbl	%ah, %esi
	rolw	$8, %r12w
	xorl	%eax, %eax
	call	printf@PLT
	movzwl	%r12w, %esi
	leaq	.LC36(%rip), %rdi
	xorl	%eax, %eax
	call	printf@PLT
	movzwl	2(%rsp), %r12d
	rolw	$8, %r12w
	movzwl	%r12w, %r12d
	subl	%ebp, %r12d
.L111:
	testl	%r12d, %r12d
	jle	.L99
	cmpl	%r12d, 1544(%rbx)
	jge	.L124
.L99:
	addq	$64, %rsp
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r13
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L122:
	.cfi_restore 3
	.cfi_restore 6
	.cfi_restore 12
	.cfi_restore 13
	.cfi_restore 14
	leaq	.LC15(%rip), %rdi
	jmp	puts@PLT
	.p2align 4,,10
	.p2align 3
.L105:
	.cfi_def_cfa_offset 112
	.cfi_offset 3, -48
	.cfi_offset 6, -40
	.cfi_offset 12, -32
	.cfi_offset 13, -24
	.cfi_offset 14, -16
	leaq	.LC22(%rip), %rdi
	call	puts@PLT
	movslq	%ebp, %rax
	movslq	1544(%rbx), %rcx
	leaq	.LC23(%rip), %rdi
	leaq	34(%rax), %rdx
	cmpq	%rdx, %rcx
	jb	.L120
	leaq	14(%rbx,%rax), %rdx
	movdqu	(%rdx), %xmm1
	movl	16(%rdx), %edx
	movaps	%xmm1, 32(%rsp)
	movzbl	44(%rsp), %esi
	movl	%edx, 48(%rsp)
	shrb	$4, %sil
	movzbl	%sil, %esi
	sall	$2, %esi
	leal	-20(%rsi), %edx
	cmpl	$40, %edx
	ja	.L125
	movzwl	2(%rsp), %r12d
	movslq	%esi, %rdx
	addl	%ebp, %esi
	leaq	14(%rax,%rdx), %r13
	rolw	$8, %r12w
	addq	%rbx, %r13
	movzwl	%r12w, %r12d
	subl	%esi, %r12d
	jmp	.L111
	.p2align 4,,10
	.p2align 3
.L106:
	leaq	.LC25(%rip), %rdi
	call	puts@PLT
	movslq	%ebp, %rax
	movslq	1544(%rbx), %rdx
	leaq	.LC26(%rip), %rdi
	leaq	22(%rax), %r14
	cmpq	%r14, %rdx
	jb	.L120
	movq	14(%rbx,%rax), %r13
	leaq	.LC27(%rip), %rdi
	xorl	%eax, %eax
	movl	%r13d, %esi
	movq	%r13, %r12
	rolw	$8, %si
	shrq	$32, %r12
	movzwl	%si, %esi
	rolw	$8, %r12w
	call	printf@PLT
	movl	%r13d, %esi
	xorl	%eax, %eax
	movzwl	%r12w, %r12d
	shrl	$16, %esi
	leaq	.LC28(%rip), %rdi
	shrq	$48, %r13
	rolw	$8, %si
	rolw	$8, %r13w
	movzwl	%si, %esi
	call	printf@PLT
	movl	%r12d, %esi
	leaq	.LC29(%rip), %rdi
	xorl	%eax, %eax
	call	printf@PLT
	xorl	%eax, %eax
	movzwl	%r13w, %esi
	leaq	.LC30(%rip), %rdi
	call	printf@PLT
	cmpl	$7, %r12d
	jle	.L113
	leal	14(%r12,%rbp), %eax
	leaq	(%rbx,%r14), %r13
	subl	$8, %r12d
	cmpl	1544(%rbx), %eax
	jle	.L111
.L113:
	leaq	.LC31(%rip), %rdi
	jmp	.L120
	.p2align 4,,10
	.p2align 3
.L124:
	movl	%r12d, %esi
	leaq	.LC38(%rip), %rdi
	xorl	%eax, %eax
	call	printf@PLT
	addq	$64, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 48
	movl	%r12d, %esi
	movq	%r13, %rdi
	popq	%rbx
	.cfi_restore 3
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_restore 6
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_restore 12
	.cfi_def_cfa_offset 24
	popq	%r13
	.cfi_restore 13
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_restore 14
	.cfi_def_cfa_offset 8
	jmp	print_payload
.L125:
	.cfi_restore_state
	leaq	.LC24(%rip), %rdi
	jmp	.L121
	.cfi_endproc
.LFE32:
	.size	process_packet, .-process_packet
	.section	.rodata.str1.1
.LC39:
	.string	"PACKET SIZE : %u bytes\n"
.LC40:
	.string	"%H:%M:%S"
	.section	.rodata.str1.8
	.align 8
.LC41:
	.string	"\npacket_t Time Stamp: %s.%06ld\n"
	.align 8
.LC42:
	.string	"\n-------------------------------------------------------------------"
	.text
	.p2align 4
	.globl	dequeue_ring_buffer
	.type	dequeue_ring_buffer, @function
dequeue_ring_buffer:
.LFB34:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movl	$3518437209, %r14d
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	leaq	16640016+ring_buffer(%rip), %rbx
	leaq	-16640016(%rbx), %r15
	leaq	88(%rbx), %rbp
	subq	$200, %rsp
	.cfi_def_cfa_offset 256
	.p2align 4,,10
	.p2align 3
.L131:
	movq	%rbx, %rdi
	call	pthread_mutex_lock@PLT
	movl	16640008+ring_buffer(%rip), %eax
	testl	%eax, %eax
	je	.L127
	jmp	.L128
	.p2align 4,,10
	.p2align 3
.L129:
	movq	%rbx, %rsi
	movq	%rbp, %rdi
	call	pthread_cond_wait@PLT
	movl	16640008+ring_buffer(%rip), %eax
	testl	%eax, %eax
	jne	.L128
.L127:
	movzbl	16640012+ring_buffer(%rip), %eax
	testb	%al, %al
	je	.L129
	movl	16640008+ring_buffer(%rip), %eax
	testl	%eax, %eax
	jne	.L128
	movzbl	16640012+ring_buffer(%rip), %eax
	testb	%al, %al
	jne	.L130
	movl	16640008+ring_buffer(%rip), %eax
.L128:
	movl	16640004+ring_buffer(%rip), %r12d
	subl	$1, %eax
	movq	%rbx, %rdi
	leaq	16(%rsp), %r13
	movl	%eax, 16640008+ring_buffer(%rip)
	leal	1(%r12), %edx
	movq	%rdx, %rsi
	imulq	%r14, %rdx
	shrq	$45, %rdx
	imull	$10000, %edx, %edx
	subl	%edx, %esi
	movl	%esi, 16640004+ring_buffer(%rip)
	call	pthread_mutex_unlock@PLT
	movl	$10, %edi
	call	putchar@PLT
	movl	%r12d, %eax
	leaq	.LC39(%rip), %rdi
	leaq	(%rax,%rax,2), %rdx
	leaq	(%rax,%rdx,4), %rdx
	xorl	%eax, %eax
	salq	$7, %rdx
	leaq	(%r15,%rdx), %r12
	movl	1544(%r12), %esi
	call	printf@PLT
	movq	%r12, %rdi
	call	process_packet
	movq	%rsp, %rdi
	movq	%r13, %rsi
	movdqa	1552(%r12), %xmm0
	leaq	80(%rsp), %r12
	movaps	%xmm0, (%rsp)
	call	localtime_r@PLT
	movq	%r13, %rcx
	movq	%r12, %rdi
	movl	$100, %esi
	leaq	.LC40(%rip), %rdx
	call	strftime@PLT
	movq	8(%rsp), %rdx
	movq	%r12, %rsi
	xorl	%eax, %eax
	leaq	.LC41(%rip), %rdi
	call	printf@PLT
	leaq	.LC42(%rip), %rdi
	call	puts@PLT
	jmp	.L131
.L130:
	movq	%rbx, %rdi
	call	pthread_mutex_unlock@PLT
	addq	$200, %rsp
	.cfi_def_cfa_offset 56
	xorl	%eax, %eax
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE34:
	.size	dequeue_ring_buffer, .-dequeue_ring_buffer
	.section	.rodata.str1.8
	.align 8
.LC43:
	.string	"Error: incude protocol for filtering , e.g 'udp', 'tcp"
	.section	.rodata.str1.1
.LC44:
	.string	"Usage: make -PF <filter>"
	.section	.rodata.str1.8
	.align 8
.LC45:
	.string	"Error creating capture thread\n"
	.align 8
.LC46:
	.string	"Error creating consumer thread\n"
	.section	.rodata.str1.1
.LC47:
	.string	"Erro joining producer thread\n"
	.section	.rodata.str1.8
	.align 8
.LC48:
	.string	"Error joining consumer thread\n"
	.section	.text.startup,"ax",@progbits
	.p2align 4
	.globl	main
	.type	main, @function
main:
.LFB35:
	.cfi_startproc
	pushq	%r13
	.cfi_def_cfa_offset 16
	.cfi_offset 13, -16
	pushq	%r12
	.cfi_def_cfa_offset 24
	.cfi_offset 12, -24
	pushq	%rbp
	.cfi_def_cfa_offset 32
	.cfi_offset 6, -32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	.cfi_offset 3, -40
	subq	$24, %rsp
	.cfi_def_cfa_offset 64
	cmpl	$2, %edi
	jne	.L143
	leaq	16640016+ring_buffer(%rip), %r13
	movq	%rsi, %rbx
	xorl	%esi, %esi
	movq	%r13, %rdi
	leaq	40(%r13), %r12
	call	pthread_mutex_init@PLT
	leaq	48(%r12), %rbp
	xorl	%esi, %esi
	movq	%r12, %rdi
	call	pthread_cond_init@PLT
	xorl	%esi, %esi
	movq	%rbp, %rdi
	call	pthread_cond_init@PLT
	movq	8(%rbx), %rcx
	xorl	%esi, %esi
	movq	%rsp, %rdi
	leaq	capture_packets(%rip), %rdx
	call	pthread_create@PLT
	testl	%eax, %eax
	jne	.L144
	xorl	%ecx, %ecx
	leaq	8(%rsp), %rdi
	leaq	dequeue_ring_buffer(%rip), %rdx
	xorl	%esi, %esi
	call	pthread_create@PLT
	testl	%eax, %eax
	jne	.L145
	movq	(%rsp), %rdi
	xorl	%esi, %esi
	call	pthread_join@PLT
	testl	%eax, %eax
	jne	.L146
	movq	8(%rsp), %rdi
	xorl	%esi, %esi
	call	pthread_join@PLT
	testl	%eax, %eax
	jne	.L147
	movq	%r13, %rdi
	call	pthread_mutex_destroy@PLT
	movq	%r12, %rdi
	call	pthread_cond_destroy@PLT
	movq	%rbp, %rdi
	call	pthread_cond_destroy@PLT
	addq	$24, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 40
	xorl	%eax, %eax
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%rbp
	.cfi_def_cfa_offset 24
	popq	%r12
	.cfi_def_cfa_offset 16
	popq	%r13
	.cfi_def_cfa_offset 8
	ret
.L143:
	.cfi_restore_state
	leaq	.LC43(%rip), %rdi
	call	puts@PLT
	leaq	.LC44(%rip), %rdi
	call	puts@PLT
	movl	$1, %edi
	call	exit@PLT
.L147:
	movq	stderr(%rip), %rcx
	movl	$30, %edx
	movl	$1, %esi
	leaq	.LC48(%rip), %rdi
	call	fwrite@PLT
	movl	$1, %edi
	call	exit@PLT
.L146:
	movq	stderr(%rip), %rcx
	movl	$29, %edx
	movl	$1, %esi
	leaq	.LC47(%rip), %rdi
	call	fwrite@PLT
	movl	$1, %edi
	call	exit@PLT
.L145:
	movq	stderr(%rip), %rcx
	movl	$31, %edx
	movl	$1, %esi
	leaq	.LC46(%rip), %rdi
	call	fwrite@PLT
	movl	$1, %edi
	call	exit@PLT
.L144:
	movq	stderr(%rip), %rcx
	movl	$30, %edx
	movl	$1, %esi
	leaq	.LC45(%rip), %rdi
	call	fwrite@PLT
	movl	$1, %edi
	call	exit@PLT
	.cfi_endproc
.LFE35:
	.size	main, .-main
	.data
	.align 4
	.type	count.0, @object
	.size	count.0, 4
count.0:
	.long	1
	.local	ring_buffer
	.comm	ring_buffer,16640256,64
	.globl	lock
	.bss
	.align 32
	.type	lock, @object
	.size	lock, 40
lock:
	.zero	40
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
