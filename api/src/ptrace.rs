use futures::future::Future;
use futures::task::{Context, Poll};

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{Pid};

use core::pin::Pin;

use log::trace;

use crate::task::*;

/// Future representing calling ptrace() and waitpid() on a Pid.
pub struct AsyncPtrace {
    pid: Pid,
}

impl AsyncPtrace {
    pub fn new(pid: Pid) -> Self {
        AsyncPtrace {
            pid
        }
    }
    pub fn getpid(&self) -> Pid {
        self.pid
    }
}

impl Future for AsyncPtrace {
    type Output = WaitStatus;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        trace!("AsyncPtrace polling once for: {}", self.getpid());
        match waitpid(self.getpid(), Some(WaitPidFlag::WNOHANG)).expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => {
                Poll::Pending
            }
            w => Poll::Ready(w),
        }
    }
}
