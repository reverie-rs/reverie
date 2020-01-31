//! provide APIs to disable VDSOs at runtime.
use libc;
use procfs;

use goblin::elf::Elf;
use log::debug;
use nix::unistd;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::vec::Vec;

use reverie_api::remote::*;
use reverie_api::task::Task;

use syscalls::*;

use crate::traced_task::TracedTask;

/*
 * byte code for the new psudo vdso functions
 * which do the actual syscalls.
 * NB: the byte code must be 8 bytes
 * aligned
 */

#[allow(non_upper_case_globals)]
const __vdso_time: &[u8] = &[
    0xb8, 0xc9, 0x0, 0x0, 0x0, // mov %SYS_time, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

#[allow(non_upper_case_globals)]
const __vdso_clock_gettime: &[u8] = &[
    0xb8, 0xe4, 0x00, 0x00, 0x00, // mov SYS_clock_gettime, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

#[allow(non_upper_case_globals)]
const __vdso_getcpu: &[u8] = &[
    0x48, 0x85, 0xff, // test %rdi, %rdi
    0x74, 0x06, // je ..
    0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, // movl $0x0, (%rdi)
    0x48, 0x85, 0xf6, // test %rsi, %rsi
    0x74, 0x06, // je ..
    0xc7, 0x06, 0x00, 0x00, 0x00, 0x00, // movl $0x0, (%rsi)
    0x31, 0xc0, // xor %eax, %eax
    0xc3, // retq
    0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
]; // nopl 0x0(%rax)

#[allow(non_upper_case_globals)]
const __vdso_gettimeofday: &[u8] = &[
    0xb8, 0x60, 0x00, 0x00, 0x00, // mov SYS_gettimeofday, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

const VDSO_SYMBOLS: &[&str] = &[
    "__vdso_time",
    "__vdso_clock_gettime",
    "__vdso_getcpu",
    "__vdso_gettimeofday",
];

lazy_static! {
    static ref VDSO_PATCH_INFO: HashMap<String, (u64, usize, &'static [u8])> = {
        let info = vdso_get_symbols_info();
        let mut res: HashMap<String, (u64, usize, &'static [u8])> =
            HashMap::new();
        let funcs = &[
            __vdso_time,
            __vdso_clock_gettime,
            __vdso_getcpu,
            __vdso_gettimeofday,
        ];
        VDSO_SYMBOLS.iter().zip(funcs).for_each(|(k, v)| {
            let name = String::from(*k);
            if let Some(&(base, size)) = info.get(&name) {
                assert!(v.len() <= size);
                res.insert(String::from(*k), (base, size, v));
            }
        });
        res
    };
}

// get vdso symbols offset/size from current process
// assuming vdso binary is the same for all processes
// so that we don't have to decode vdso for each process
fn vdso_get_symbols_info() -> HashMap<String, (u64, usize)> {
    let mut res: HashMap<String, (u64, usize)> = HashMap::new();
    procfs::process::Process::new(unistd::getpid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .find(|e| e.pathname == procfs::process::MMapPath::Vdso)
        .and_then(|vdso| {
            let slice = unsafe {
                std::slice::from_raw_parts(
                    vdso.address.0 as *mut u8,
                    (vdso.address.1 - vdso.address.0) as usize,
                )
            };
            Elf::parse(slice)
                .map(|elf| {
                    let strtab = elf.dynstrtab;
                    elf.dynsyms.iter().for_each(|sym| {
                        let sym_name = &strtab[sym.st_name];
                        if VDSO_SYMBOLS.contains(&&sym_name) {
                            debug_assert!(sym.is_function());
                            res.insert(
                                String::from(sym_name),
                                (sym.st_value, sym.st_size as usize),
                            );
                        }
                    });
                })
                .ok()
        });
    res
}

#[test]
fn can_find_vdso() {
    assert!(procfs::process::Process::new(unistd::getpid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .filter(|e| e.pathname == procfs::process::MMapPath::Vdso)
        .next()
        .is_some());
}

#[test]
fn vdso_can_find_symbols_info() {
    let info = vdso_get_symbols_info();
    assert!(info.len() > 0);
}

#[test]
fn vdso_patch_info_is_valid() {
    let info = &VDSO_PATCH_INFO;
    info.iter().for_each(|i| println!("info: {:x?}", i));
    assert!(info.len() > 0);
}

/// patch VDSOs when enabled
///
/// `task` must be in stopped state.
pub fn vdso_patch(task: &mut TracedTask) -> Result<()> {
    if let Some(vdso) = procfs::process::Process::new(task.getpid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .find(|e| e.pathname == procfs::process::MMapPath::Vdso)
    {
        task.untraced_syscall(
            SYS_mprotect,
            vdso.address.0 as u64,
            (vdso.address.1 - vdso.address.0) as u64,
            u64::from(
                (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32,
            ),
            0,
            0,
            0,
        )
        .unwrap();
        for (name, (offset, size, bytes)) in VDSO_PATCH_INFO.iter() {
            let start = vdso.address.0 + offset;
            assert!(bytes.len() <= *size);
            let rptr = Remoteable::remote(start as *mut u8).unwrap();
            task.poke_bytes(rptr, bytes).unwrap();
            assert!(*size >= bytes.len());
            if *size > bytes.len() {
                let fill: Vec<u8> = std::iter::repeat(0x90u8)
                    .take(size - bytes.len())
                    .collect();
                unsafe {
                    task.poke_bytes(
                        rptr.offset(bytes.len() as isize),
                        fill.as_slice(),
                    )
                    .unwrap();
                }
            }
            debug!("{} patched {}@{:x}", task.getpid(), name, start);
        }
        task.untraced_syscall(
            SYS_mprotect,
            vdso.address.0,
            vdso.address.1 - vdso.address.0,
            (libc::PROT_READ | libc::PROT_EXEC) as u64,
            0,
            0,
            0,
        )
        .unwrap();
    }
    Ok(())
}
