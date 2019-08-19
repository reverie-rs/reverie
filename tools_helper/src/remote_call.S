	.extern _raw_syscall
	.global _remote_syscall_helper
	.type _remote_syscall_helper, @function
/*
  void _remote_syscall_helper(struct syscall_info* info) ;
*/
_remote_syscall_helper:
	// NB: assume stack is aligned
	// return_address   // rsp + 0x88
	/* syscall_info */
	// info-> no   // rsp + 0x80
	// info-> arg0 // rsp + 0x78
	// info-> arg1 // rsp + 0x70
	// info-> arg2 // rsp + 0x68
	// info-> arg3 // rsp + 0x60
	// info-> arg4 // rsp + 0x58
	// info-> arg5 // rsp + 0x50
	// info-> pad  // rsp + 0x48
	push %rax      // rsp + 0x40
	push %rdi      // rsp + 0x38
	push %rsi      // rsp + 0x30
	push %rdx      // rsp + 0x28
	push %rcx      // rsp + 0x20
	push %r8       // rsp + 0x18
	push %r9       // rsp + 0x10
	push %r10      // rsp + 0x8
	push %r11      // rsp + 0

	movq 0x80(%rsp), %rdi        // info->no
	movq 0x78(%rsp), %rsi        // info->arg0
	movq 0x70(%rsp), %rdx        // info->arg1
	movq 0x68(%rsp), %rcx        // info->arg2
	movq 0x60(%rsp), %r8         // info->arg3
	movq 0x58(%rsp), %r9         // info->arg4
	movq $0, %r11
	push %r11        // 10th argument
	push %r11        // 9th argument
	movq $0x70000000, %r11
	push %r11        // 8th
	movq 0x50(%rsp), %r11        // info->arg5
	push %r11        // 7th
	callq _raw_syscall
	add  $0x20, %rsp  // addtional arguments+alignment

	pop  %r11
	pop  %r10
	pop  %r9
	pop  %r8
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax
	add  $0x40, %rsp
	retq

	.global _remote_funccall_helper
	.type _remote_funccall_helper, @function
/*
  void _remote_syscall_helper(struct syscall_info* info) ;
*/
_remote_funccall_helper:
	// NB: assume stack is aligned

	// new stack layout   // caller to populate
	// +-------------+    // top (high address, aligned)
	// |             |
	// ~    4096B    ~    // xsave area
	// |             |
	// +-------------+
	// |     8B      |    // reseved 8B                    SP[0x48]
	// +-------------+
	// |     8B      |    // previous stack pointer        SP[0x40]
	// +-------------+
	// |     8B      |    // Arg6       SP[0x38]
	// +-------------+
	// |     8B      |    // Arg5       SP[0x30]
	// +-------------+
	// |     8B      |    // Arg4       SP[0x28]
	// +-------------+
	// |     8B      |    // Arg3       SP[0x20]
	// +-------------+
	// |     8B      |    // Arg2       SP[0x18]
	// +-------------+
	// |     8B      |    // Arg1       SP[0x10]
	// +-------------+
	// |     8B      |    // func addr  SP[0x8]
	// +-------------+
	// |             |    // SP (+8 = aligned)
	// ~             ~
	//!

	// old stack layout, caller to populate
	// +-------------+
	// |     8B      |     // return address
	// +-------------+
	// |     8B      |     // new stack pointer
	// +-------------+
	// |     8B      |     // padding
	// +-------------+
	// |             |     // SP   <aligned>
	// ~             ~
	//!

	push %rbx                // callee saved, must restore
	movq 0x10(%rsp), %rbx    // stack to switch to
	movq %rbx, %rsp

	push %rax      // rsp + 0x40
	push %rdi      // rsp + 0x38
	push %rsi      // rsp + 0x30
	push %rdx      // rsp + 0x28
	push %rcx      // rsp + 0x20
	push %r8       // rsp + 0x18
	push %r9       // rsp + 0x10
	push %r10      // rsp + 0x8
	push %r11      // rsp + 0

//#ifdef USE_XSAVE
	// save extended registers
	movq $0xffffffffffffffff, %rax
	movq %rax, %rdx
	xsave 0x90(%rsp)            // must be 512B aligned
//#endif

	movq 0x48(%rsp), %r10        // func
	movq 0x50(%rsp), %rdi        // info->arg0
	movq 0x58(%rsp), %rsi        // info->arg1
	movq 0x60(%rsp), %rdx        // info->arg2
	movq 0x68(%rsp), %rcx        // info->arg3
	movq 0x70(%rsp), %r8         // info->arg4
	movq 0x78(%rsp), %r9         // info->arg5

	// rsp must be aligned
	callq *%r10

	// save return values
	movq %rax, 0x48(%rsp)
	movq %rdx, 0x50(%rsp)

//#ifdef USE_XSAVE
	// restore extended registers
	movq $0xffffffffffffffff, %rax
	movq %rax, %rdx
	xrstor 0x90(%rsp)            // must be 512B aligned
//#endif

	movq 0x80(%rsp), %rbx        // old rsp

	pop  %r11
	pop  %r10
	pop  %r9
	pop  %r8
	pop  %rcx
	pop  %rdx
	pop  %rsi
	pop  %rdi
	pop  %rax

	// restore old rsp
	leaq -0x8(%rbx), %rsp
	// restore rbx
	movq 0x0(%rsp), %rbx
	add  $0x18, %rsp  // new stack pointer + padding
	retq
