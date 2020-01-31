/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * 
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

//! linux syscall Arguments formatter

mod args;
mod fcntl;
mod ioctl;
mod types;

/// `SyscallArg` type
pub use types::SyscallArg;
/// `SyscallInfo` type include arguments and syscall number.
pub use types::SyscallInfo;
/// `SyscallRet` type
pub use types::SyscallRet;
pub use types::SyscallRetInfo;
