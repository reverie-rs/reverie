/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

//! convenient functions for debugging tracees

use reverie_api::remote::*;
use reverie_api::task::Task;

use crate::traced_task::TracedTask;
use log::debug;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::unistd::Pid;

// TODO: could check whether or not stack is valid
fn show_stackframe(
    tid: Pid,
    stack: u64,
    top_size: usize,
    bot_size: usize,
) -> String {
    let mut text = String::new();
    if stack < top_size as u64 {
        return text;
    }
    let sp_top = stack - top_size as u64;
    let sp_bot = stack + bot_size as u64;
    let mut sp = sp_top;

    while sp <= sp_bot {
        match ptrace::read(tid, sp as ptrace::AddressType) {
            Err(_) => break,
            Ok(x) => {
                if sp == stack {
                    text += &format!(" => {:12x}: {:16x}\n", sp, x);
                } else {
                    text += &format!("    {:12x}: {:16x}\n", sp, x);
                }
            }
        }
        sp += 8;
    }
    text
}

fn show_user_regs(regs: &libc::user_regs_struct) -> String {
    let mut res = String::new();

    res += &format!(
        "rax {:16x} rbx {:16x} rcx {:16x} rdx {:16x}\n",
        regs.rax, regs.rbx, regs.rcx, regs.rdx
    );
    res += &format!(
        "rsi {:16x} rdi {:16x} rbp {:16x} rsp {:16x}\n",
        regs.rsi, regs.rdi, regs.rbp, regs.rsp
    );
    res += &format!(
        " r8 {:16x}  r9 {:16x} r10 {:16x} r11 {:16x}\n",
        regs.r8, regs.r9, regs.r10, regs.r11
    );
    res += &format!(
        "r12 {:16x} r13 {:16x} r14 {:16x} r15 {:16x}\n",
        regs.r12, regs.r13, regs.r14, regs.r15
    );
    res += &format!("rip {:16x} eflags {:16x}\n", regs.rip, regs.eflags);
    res += &format!(
        "cs {:x} ss {:x} ds {:x} es {:x}\nfs {:x} gs {:x}",
        regs.cs, regs.ss, regs.ds, regs.es, regs.fs, regs.gs
    );
    res
}

fn show_proc_maps(maps: &procfs::process::MemoryMap) -> String {
    use procfs::process::MMapPath;
    let mut res = String::new();
    let fp = match &maps.pathname {
        MMapPath::Path(path) => String::from(path.to_str().unwrap_or("")),
        MMapPath::Vdso => String::from("[vdso]"),
        MMapPath::Vvar => String::from("[vvar]"),
        MMapPath::Vsyscall => String::from("[vsyscall]"),
        MMapPath::Stack => String::from("[stack]"),
        MMapPath::Other(s) => s.clone(),
        _ => String::from(""),
    };
    let s = format!(
        "{:x}-{:x} {} {:08x} {:02x}:{:02x} {}",
        maps.address.0,
        maps.address.1,
        maps.perms,
        maps.offset,
        maps.dev.0,
        maps.dev.1,
        maps.inode
    );
    res.push_str(&s);
    (0..=72 - s.len()).for_each(|_| res.push(' '));
    res.push_str(&fp);
    res
}

fn task_rip_is_valid(task: &TracedTask, rip: u64) -> bool {
    let mut has_valid_rip = None;
    if let Ok(mapping) = procfs::process::Process::new(task.getpid().as_raw())
        .and_then(|p| p.maps())
    {
        has_valid_rip = mapping
            .iter()
            .find(|e| {
                e.perms.contains('x')
                    && e.address.0 <= rip
                    && e.address.1 > rip + 0x10
            })
            .cloned();
    }
    has_valid_rip.is_some()
}

pub fn show_fault_context(task: &TracedTask, sig: signal::Signal) {
    let regs = task.getregs().unwrap();
    let siginfo = task.getsiginfo().unwrap();
    let tid = task.gettid();
    debug!(
        "{:?} got {:?} si_errno: {}, si_code: {}, regs\n{}",
        task,
        sig,
        siginfo.si_errno,
        siginfo.si_code,
        show_user_regs(&regs)
    );

    debug!(
        "stackframe from rsp@{:x}\n{}",
        regs.rsp,
        show_stackframe(tid, regs.rsp, 0x40, 0x80)
    );

    if task_rip_is_valid(task, regs.rip) {
        if let Some(rptr) = Remoteable::remote(regs.rip as *mut u8) {
            match task.peek_bytes(rptr, 16) {
                Err(_) => (),
                Ok(v) => {
                    debug!("insn @{:x?} = {:02x?}", rptr.as_ptr(), v);
                }
            }
        }
    } else {
        debug!("insn @{:x?} = <invalid rip>", regs.rip);
    }

    procfs::process::Process::new(task.getpid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .for_each(|e| {
            debug!("{}", show_proc_maps(e));
        });
}
