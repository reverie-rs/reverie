//! api

#![feature(async_await, pin_into_inner)]
#![allow(unused_imports)]

use nix::unistd::Pid;
use std::marker::PhantomData;
use std::ptr::NonNull;

pub mod task;
pub mod remote;
pub mod ptrace;
mod consts;

pub use crate::consts::*;
