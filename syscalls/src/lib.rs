#![cfg_attr(not(feature = "std"), no_std)]

#![feature(asm)]

#[macro_use]

pub mod helper;
pub mod nr;
pub mod macros;

pub use self::nr::*;
pub use self::nr::SyscallNo::*;
pub use self::helper::*;
