//! ptraced based rpc
//!
//! tracer can do arbitrary function calls
//! inside tracee
//!
//! NB: the tracee must be in a ptrace stop
//!

use crate::remote::*;
use crate::task::Task;
use crate::traced_task::TracedTask;
use crate::consts;
use nix::sys::wait;
use nix::sys::signal;
use nix::sys::ptrace;

pub unsafe fn rpc_call(task: &TracedTask, func: u64, args: &[u64; 6]) -> i64 {
    if let Some((top, _)) = task.rpc_stack {
        let mut regs = task.getregs().unwrap();
        let new_sp = top.as_ptr() as u64 - 0x1000;
        // println!("old_sp: {:x?}, new_sp: {:x?}, top: {:x?}", regs.rsp, new_sp, top);
        let sp_addr = new_sp as u64 - 9 * core::mem::size_of::<u64>() as u64;
        let old_sp_adjusted = regs.rsp - 3 * core::mem::size_of::<u64>() as u64;
        let sp = RemotePtr::new(sp_addr as *mut u64);
        let data_to_write: Vec<u64> = vec![func, args[0], args[1], args[2],
                                           args[3], args[4], args[5],
                                           old_sp_adjusted, 0xdeadbeef];
        data_to_write.iter().enumerate().for_each(|(k, v)| {
            let at = sp.offset(k as isize);
            // println!("write {:x?} = {:x}", at, v);
            task.poke(at, v).unwrap();
        });

        let sp = RemotePtr::new(old_sp_adjusted as *mut u64);
        let data_to_write: Vec<u64> = vec![0xcafebabe, sp_addr as u64, regs.rip];
        data_to_write.iter().enumerate().for_each(|(k, v)| {
            let at = sp.offset(k as isize);
            // println!("write {:x?} = {:x}", at, v);
            task.poke(at, v).unwrap();
        });
        let syscall_helper_addr_ptr = RemotePtr::new(consts::SYSTRACE_LOCAL_RPC_HELPER as *mut u64);
        let syscall_helper_addr = task.peek(syscall_helper_addr_ptr).unwrap();
        regs.rip = syscall_helper_addr;
        regs.rsp = old_sp_adjusted;
        task.setregs(regs).unwrap();
    }
    0
}
