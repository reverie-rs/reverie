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

//! ptraced based rpc
//!
//! tracer can do arbitrary function calls
//! inside tracee
//!
//! NB: the tracee must be in a ptrace stop
//!

use reverie_api::remote::*;
use reverie_api::task::Task;
use reverie_common::consts;

use crate::traced_task::TracedTask;

use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait;

pub unsafe fn rpc_call(task: &TracedTask, func: u64, args: &[u64; 6]) -> i64 {
    if let Some((top, _)) = task.rpc_stack {
        let mut regs = task.getregs().unwrap();
        let new_sp = top.as_ptr() as u64 - 0x1000;
        // println!("old_sp: {:x?}, new_sp: {:x?}, top: {:x?}", regs.rsp, new_sp, top);
        let sp_addr = new_sp as u64 - 9 * core::mem::size_of::<u64>() as u64;
        let old_sp_adjusted = regs.rsp - 3 * core::mem::size_of::<u64>() as u64;
        let sp = Remoteable::remote(sp_addr as *mut u64).unwrap();
        let data_to_write: Vec<u64> = vec![
            func,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            old_sp_adjusted,
            0xdeadbeef,
        ];
        data_to_write.iter().enumerate().for_each(|(k, v)| {
            let at = sp.offset(k as isize);
            // println!("write {:x?} = {:x}", at, v);
            task.poke(at, v).unwrap();
        });

        let sp = Remoteable::remote(old_sp_adjusted as *mut u64).unwrap();
        let data_to_write: Vec<u64> =
            vec![0xcafebabe, sp_addr as u64, regs.rip];
        data_to_write.iter().enumerate().for_each(|(k, v)| {
            let at = sp.offset(k as isize);
            // println!("write {:x?} = {:x}", at, v);
            task.poke(at, v).unwrap();
        });
        let syscall_helper_addr_ptr =
            Remoteable::remote(consts::REVERIE_LOCAL_RPC_HELPER as *mut u64)
                .unwrap();
        let syscall_helper_addr = task.peek(syscall_helper_addr_ptr).unwrap();
        regs.rip = syscall_helper_addr;
        regs.rsp = old_sp_adjusted;
        task.setregs(regs).unwrap();
    }
    0
}
