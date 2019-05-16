#![feature(format_args_nl, slice_internals)]

/// systrace tools helper
#[macro_use]
pub mod stdio;
pub mod logger;
pub mod spinlock;
pub mod consts;
pub mod local_state;
pub mod counter;

pub use counter::note_syscall;
pub use counter::NoteInfo;
pub use local_state::LocalState;
