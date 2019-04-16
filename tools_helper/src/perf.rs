/// linux perf events

use crate::consts;
use syscalls::*;

pub const PERF_EVENT_IOC_RESET: u64 = 9219u64;
pub const PERF_EVENT_IOC_ENABLE: u64 = 9216u64;
pub const PERF_EVENT_IOC_DISABLE: u64 = 9217u64;

pub struct DeschedEvent {}

impl DeschedEvent {
    pub fn new() -> Self {
        enable_desched_event();
        DeschedEvent{}
    }
}

impl Drop for DeschedEvent {
    fn drop(&mut self) {
        disable_desched_event();
    }
}

fn enable_desched_event() {
    let fd = consts::SYSTRACE_CTSW_SIGNAL_FD as i64;
    syscall(SYS_ioctl as i32, fd, PERF_EVENT_IOC_ENABLE as i64,
            0, 0, 0, 0).expect("ioctl perf_event enable");
}

fn disable_desched_event() {
    let fd = consts::SYSTRACE_CTSW_SIGNAL_FD as i64;
    syscall(SYS_ioctl as i32, fd, PERF_EVENT_IOC_DISABLE as i64,
            0, 0, 0, 0).expect("ioctl perf_event disable");
}
