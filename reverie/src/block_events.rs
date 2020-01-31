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

pub enum BlockingEvents {
    BlockOnFdRead(i32),
    BlockOnFdWrite(i32),
    BlockOnFdPri(i32),

    // waitpid
    BlockOnPid(u32),
    BlockOnAnyChild,
    BlockOnAnyChildPgid(u32),

    BlockOnTimeoutRel(u64),

    // futex
    BlockOnFutexWait(u64, u64),
    BlockOnFutexWaitBit(u64, u64),
    BlockOnFutexLockPI(u64),

    BlockOnSignal(u64),
}
