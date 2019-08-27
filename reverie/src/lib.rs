#![allow(unused_imports)]
#![allow(dead_code)]

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_arguments))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::inconsistent_digit_grouping))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::let_and_return))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]

#[macro_use]
extern crate lazy_static;

pub use reverie_syscalls;
pub use reverie_common;

pub mod hooks;
pub mod nr;
pub mod ns;
pub mod remote;
pub mod remote_rwlock;
pub mod sched;
pub mod sched_wait;
pub mod stubs;
pub mod vdso;
pub mod task;
pub mod traced_task;
pub mod block_events;
pub mod rpc_ptrace;
pub mod auxv;
pub mod aux;
pub mod config;
pub mod debug;
