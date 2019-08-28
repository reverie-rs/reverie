use futures::future::Future;
use futures::future::BoxFuture;
use futures::task::{Context, Poll, ArcWake};

use nix::errno::Errno;
use nix::unistd::{Pid};
use nix::Error::Sys;

use std::sync::Arc;

use std::cell::RefCell;
use std::collections::HashMap;

use log::{debug, trace};

unsafe fn si_pid(info: &libc::siginfo_t) -> Pid {
    let ptr = (info as *const libc::siginfo_t as  *const i32).offset(4);
    Pid::from_raw(std::ptr::read(ptr))
}

/// This is our futures runtime. It is responsible for accepting futures to run,
/// polling them, registering the Pid the future is waiting for, and scheduling,
/// the next task to run.

/// This executor is meant to be used in a ptrace context. So all tasks run
/// in the main process, as child-threads of a ptracer are not allowed to ptrace or
/// wait on the tracee.
#[derive(Clone)]
pub struct WaitidExecutor {}

pub struct WaitidWaker { }

impl ArcWake for WaitidWaker {
    fn wake_by_ref(_arc_self: &Arc<Self>) {
        // We should not ever call the waker. It is all done through thread local state.
        unreachable!();
    }
}
