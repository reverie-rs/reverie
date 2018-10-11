#ifndef _MY_SYSCALLBUF_H
#define _MY_SYSCALLBUF_H

#include <sys/types.h>
#include <inttypes.h>

#define PRELOAD_PAGE_ADDR 0x70000000UL
#define PRELOAD_THREAD_LOCALS_ADDR 0x70001000UL

#define SYSCALL_UNTRACED (void*)(PRELOAD_PAGE_ADDR+0)
#define SYSCALL_TRACED   (void*)(PRELOAD_PAGE_ADDR+4)

struct syscall_info {
  unsigned long no;
  unsigned long args[6];
};

struct preload_thread_locals {
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on.
   * Offset of this field is hardcoded in syscall_hook.S and
   * assembly_templates.py.
   * Pointer to alt-stack used by syscallbuf stubs (allocated at the end of
   * the scratch buffer.
   */
  unsigned long syscallbuf_stub_alt_stack;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * tools can depend on.
   * Where syscall result will be (or during replay, has been) saved.
   */
  long pending_untraced_syscall_result;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on.
   * Scratch space used by stub code.
   */
  unsigned long stub_scratch_1;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on.
   */
  int alt_stack_nesting_level;
  /**
   * We could use this later.
   */
  int unused_padding;
  /* The offset of this field MUST NOT CHANGE, it is part of the preload ABI
   * rr depends on. It contains the parameters to the patched syscall, or
   * zero if we're not processing a buffered syscall. Do not depend on this
   * existing during replay, some traces with SYSCALLBUF_PROTOCOL_VERSION 0
   * don't have it.
   */
  const struct syscall_info* original_syscall_parameters;

  /* Nonzero when thread-local state like the syscallbuf has been
   * initialized.  */
  int thread_inited;
  /* The offset of this field MUST NOT CHANGE, it is part of the ABI tools
   * depend on. When buffering is enabled, points at the thread's mapped buffer
   * segment.  At the start of the segment is an object of type |struct
   * syscallbuf_hdr|, so |buffer| is also a pointer to the buffer
   * header. */
  unsigned char* buffer;
  size_t buffer_size;
  /* This is used to support the buffering of "may-block" system calls.
   * The problem that needs to be addressed can be introduced with a
   * simple example; assume that we're buffering the "read" and "write"
   * syscalls.
   *
   *  o (Tasks W and R set up a synchronous-IO pipe open between them; W
   *    "owns" the write end of the pipe; R owns the read end; the pipe
   *    buffer is full)
   *  o Task W invokes the write syscall on the pipe
   *  o Since write is a buffered syscall, the seccomp filter traps W
   *    directly to the kernel; there's no trace event for W delivered
   *    to rr.
   *  o The pipe is full, so W is descheduled by the kernel because W
   *    can't make progress.
   *  o rr thinks W is still running and doesn't schedule R.
   *
   * At this point, progress in the recorded application can only be
   * made by scheduling R, but no one tells rr to do that.  Oops!
   *
   * Thus enter the "desched counter".  It's a perf_event for the "sw t
   * switches" event (which, more precisely, is "sw deschedule"; it
   * counts schedule-out, not schedule-in).  We program the counter to
   * deliver a signal to this task when there's new counter data
   * available.  And we set up the "sample period", how many descheds
   * are triggered before the signal is delivered, to be "1".  This
   * means that when the counter is armed, the next desched (i.e., the
   * next time the desched counter is bumped up) of this task will
   * deliver the signal to it.  And signal delivery always generates a
   * ptrace trap, so rr can deduce that this task was descheduled and
   * schedule another.
   *
   * The description above is sort of an idealized view; there are
   * numerous implementation details that are documented in
   * handle_signal.c, where they're dealt with. */
  int desched_counter_fd;
  int cloned_file_data_fd;
  off_t cloned_file_data_offset;
  void* scratch_buf;
  size_t usable_scratch_size;

  struct msghdr* notify_control_msg;
};

struct syscall_patch_hook {
  uint8_t is_multi_instruction;
  uint8_t next_instruction_length;
  /* Avoid any padding or anything that would make the layout arch-specific. */
  uint8_t next_instruction_bytes[14];
  uint64_t hook_address;
};

#endif
