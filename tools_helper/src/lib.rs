#![feature(format_args_nl, slice_internals)]

/// systrace tools helper
#[macro_use]
pub mod stdio;
pub mod logger;
pub mod spinlock;
pub mod consts;
pub mod state;
pub mod counter;
pub mod perf;

pub use counter::note_syscall;
pub use counter::NoteInfo;
