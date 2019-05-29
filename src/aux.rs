//! auxv decoder
//!
//! the auxv is passed by linux kernel to either the dynamic linker
//! or the program's entry point (static binaries)
//!
//! to get the correct values, the decoder must be called on
//! ptrace exec event. or if you're the dynamic linker :-)
//!

use std::io::Result;
use std::collections::HashMap;

use crate::task::Task;
use crate::traced_task::TracedTask;
use crate::remote::*;

pub unsafe fn getauxval(task: &TracedTask) -> Result<HashMap<usize, u64>> {
    let mut res: HashMap<usize, u64>  = HashMap::new();
    let regs = task.getregs()?;

    let sp = RemotePtr::new(regs.rsp as *mut u64);
    let argc = task.peek(sp)?;
    let argv = sp.offset(1);
    let mut k = 1 + argc as isize;

    loop {
        let curr = argv.offset(k);
        let val = task.peek(curr)?;
        if val == 0 {
            break;
        }
        k = 1 + k;
    }
    let mut auxv = argv.offset(1 + k);

    loop {
        let key = task.peek(auxv)?;
        if key == 0 {
            break;
        }
        let val = task.peek(auxv.offset(1))?;
        res.insert(key as usize, val);
        auxv = auxv.offset(2);
    }
    Ok(res)
}
