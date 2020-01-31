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


#[macro_export]
macro_rules! remote_untraced_syscall {
    ($pid: ident, $nr:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, 0, 0, 0, 0, 0, 0) };
    ($pid: ident, $nr:expr, $a0:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, a0, 0, 0, 0, 0, 0) };
    ($pid: ident, $nr:expr, $a0:expr, $a1:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, a0, a1, 0, 0, 0, 0) };
    ($pid: ident, $nr:expr, $a0:expr, $a1:expr, $a2:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, a0, a1, a2, 0, 0, 0) };
    ($pid: ident, $nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, a0, a1, a2, a3, 0, 0) };
    ($pid: ident, $nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, a0, a1, a2, a3, a4, 0) };
    ($pid: ident, $nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => { crate::remote::remote_do_untraced_syscall($pid, $nr, a0, a1, a2, a3, a4, a5) };
}
