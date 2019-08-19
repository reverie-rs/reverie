use futures::core_reexport::pin::Pin;
use futures::future::Future;
use futures::task::{Context, Poll};

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{Pid};

use log::trace;

use crate::task::*;

impl Future for dyn Task {
    type Output = WaitStatus;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        trace!("AsyncPtrace polling once for: {}", self.gettid());
        match waitpid(self.gettid(), Some(WaitPidFlag::WNOHANG)).expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => {
                Poll::Pending
            }
            w => Poll::Ready(w),
        }
    }
}

