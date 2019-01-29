
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
