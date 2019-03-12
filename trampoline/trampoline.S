/*
 * Copyright (c) 2013 Mozilla Foundation
 * Copyright 2015 VMware, Inc
 * Copyright 2015 Google Inc.
 *
 * Contributors: Albert Noll <noll.albert@gmail.com>, Thomas Anderegg <thomas@tanderegg.com>, Nimrod Partush <nimrodpar@gmail.com>
 *               Andrew Walton <awalton@vmware.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define stub_scratch_1 0x70001010

	.text

	.global _syscall_hook_trampoline;
	.hidden _syscall_hook_trampoline;
	.type _syscall_hook_trampoline, @function;
_syscall_hook_trampoline:
        /* Save RBX because we need a callee-saves register */
        pushq %rbx

        /* Build a |struct syscall_info| on the stack by pushing the arguments
           and syscall number. */
        pushq %r9
        pushq %r8
        pushq %r10
        pushq %rdx
        pushq %rsi
        pushq %rdi
        pushq %rax

        /* Align stack */
        mov %rsp,%rbx
        and $0xfffffffffffffff0,%rsp

        /* Call our hook. */
        mov %rbx,%rdi
        callq syscall_hook

        mov %rbx,%rsp

        /* On entrance, we pushed the %rax, the syscall number. But we don't
           want to |pop %rax|, as that will overwrite our return value. Pop
           into %rbx instead. */
        pop %rbx

        /* We don't really *need* to restore these, since the kernel could have
           trashed them all anyway. But it seems reasonable to do so. */
        pop %rdi
        pop %rsi
        pop %rdx
        pop %r10
        pop %r8
        pop %r9

        pop %rbx

        /* ...and we're done. */
        ret
        .size _syscall_hook_trampoline, . - _syscall_hook_trampoline

/**
 * On syscallhook entry, the stack has been switched to the end of per-task
 * scratch space, then the old RSP and the return address have been pushed.
 */
#define SYSCALLHOOK_START(name)    \
        .global name;              \
	.hidden name;              \
        .type name, @function;     \
name:                              

#define SYSCALLHOOK_END(name)                                   \
	ret				       ;                \
        .size name, .-name

SYSCALLHOOK_START(_syscall_hook_trampoline_48_3d_01_f0_ff_ff)
        callq __morestack
        cmpq $0xfffffffffffff001,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_3d_01_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_3d_00_f0_ff_ff)
        callq __morestack
        cmpq $0xfffffffffffff000,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_3d_00_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_8b_3c_24)
         callq __morestack
         /* The original instruction after the syscall is movq (%rsp),%rdi. */
         movq 8(%rsp),%rdi
         movq %rax, %rdx
SYSCALLHOOK_END(_syscall_hook_trampoline_48_8b_3c_24)

SYSCALLHOOK_START(_syscall_hook_trampoline_5a_5e_c3)
        callq __morestack
        /* The original instructions after the syscall are
           pop %rdx; pop %rsi; retq. */
        pop (stub_scratch_1)
        pop %rdx
        pop %rsi
SYSCALLHOOK_END(_syscall_hook_trampoline_5a_5e_c3)

SYSCALLHOOK_START(_syscall_hook_trampoline_89_c2_f7_da)
        call __morestack
        mov %eax,%edx
        neg %edx
SYSCALLHOOK_END(_syscall_hook_trampoline_89_c2_f7_da)

SYSCALLHOOK_START(_syscall_hook_trampoline_90_90_90)
        call __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_90_90_90)

SYSCALLHOOK_START(_syscall_hook_trampoline_ba_01_00_00_00)
        call __morestack
        mov $1,%edx
SYSCALLHOOK_END(_syscall_hook_trampoline_ba_01_00_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_89_c1_31_d2)
        call __morestack
        mov %eax,%ecx
        xor %edx,%edx
SYSCALLHOOK_END(_syscall_hook_trampoline_89_c1_31_d2)

SYSCALLHOOK_START(_syscall_hook_trampoline_c3_nop)
        callq __morestack
        /* The original instructions after the syscall are
           retq; nopl 0x0(%rax,%rax,1) */
        pop (stub_scratch_1)
SYSCALLHOOK_END(_syscall_hook_trampoline_c3_nop)

SYSCALLHOOK_START(_syscall_hook_trampoline_85_c0_0f_94_c2)
	callq __morestack
	test %eax, %eax
	sete %dl
SYSCALLHOOK_END(_syscall_hook_trampoline_85_c0_0f_94_c2)

.global __morestack
.hidden __morestack
.type __morestack, @function
__morestack:
	// allocate extra 128-byte to avoid spilling red-zone
	// because we didn't do stack switch for trampoline
	sub $0x80, %rsp
	callq _syscall_hook_trampoline
	add $0x80, %rsp
	ret
.size __morestack, .-__morestack

