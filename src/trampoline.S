#define stub_scratch_1 0x70000100
#define syscall_hook   0x70001010

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
        callq *(syscall_hook)

        mov %rbx,%rsp

        /* On entrance, we pushed the %rax, the syscall number. But we don't
           want to |pop %rax|, as that will overwrite our return value. Pop
           into %r11 instead. */
        pop %r11

        /* We don't really *need* to restore these, since the kernel could have
           trashed them all anyway. But it seems reasonable to do so. */
        pop %rdi
        pop %rsi
        pop %rdx
        pop %r10
        pop %r8
/*
        mov (alt_stack_nesting_level),%r9d
        lea -1(%r9),%r9
        mov %r9d,(alt_stack_nesting_level)
*/
        pop %r9

        pop %rbx

        /* ...and we're done. */
        ret
        .size _syscall_hook_trampoline, . - _syscall_hook_trampoline

	.global _syscallbuf_final_exit_instruction;
	.hidden _syscallbuf_final_exit_instruction;
	.type _syscallbuf_final_exit_instruction, @function;
_syscallbuf_final_exit_instruction:
        jmp *(stub_scratch_1)

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
        pop (stub_scratch_1);                                   \
        jmp _syscallbuf_final_exit_instruction;                 \
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
         movq (%rdi),%rdi
SYSCALLHOOK_END(_syscall_hook_trampoline_48_8b_3c_24)

SYSCALLHOOK_START(_syscall_hook_trampoline_5a_5e_c3)
        callq __morestack
        /* The original instructions after the syscall are
           pop %rdx; pop %rsi; retq. */
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        pop %rdx
        pop %rsp
        pop %rdx
        pop %rsi
        pop (stub_scratch_1)
        jmp _syscallbuf_final_exit_instruction

        .size _syscall_hook_trampoline_5a_5e_c3, .-_syscall_hook_trampoline_5a_5e_c3

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
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        pop %rdx
        pop %rsp
        pop (stub_scratch_1)
        jmp _syscallbuf_final_exit_instruction

        .size _syscall_hook_trampoline_c3_nop, .-_syscall_hook_trampoline_c3_nop

.global __morestack
.hidden __morestack
.type __morestack, @function
__morestack:
	callq _syscall_hook_trampoline
	ret
.size __morestack, .-__morestack

