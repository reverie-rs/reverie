//! lookup symbols in the tool library
//!

use crate::consts;
use crate::remote::RemotePtr;
use std::ffi::c_void;
use nix::sys::ptrace;
use nix::unistd;
use std::path::PathBuf;
use procfs;
use goblin::elf::Elf;
use std::io::{Read, Error, ErrorKind, Result};
use std::fs::File;

fn dso_load_address(pid: unistd::Pid, so: &str) -> Option<u64> {
    let path = PathBuf::from(so);
    procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter().filter(|e| {
            match &e.pathname {
                procfs::MMapPath::Path(soname) => {
                    soname == &path
                }
                _ => false,
            }
        }).next().map(|e|e.address.0)
}

pub fn get_symbol_address(pid: unistd::Pid, name: &str) -> Option<RemotePtr<c_void>> {
    let so = std::env::var(consts::SYSTRACE_TRACEE_PRELOAD).ok()?;
    let la = ptrace::read(
        pid,
        consts::SYSTRACE_LOCAL_SYSCALL_TRAMPOLINE as ptrace::AddressType,
    ).ok().and_then(|addr| {
        if addr == 0 {
            None
        } else {
            dso_load_address(pid, &so)
        }
    })?;

    let mut bytes: Vec<u8> = Vec::new();
    let mut file = File::open(so).unwrap();
    file.read_to_end(&mut bytes).unwrap();
    let elf = Elf::parse(bytes.as_slice()).map_err(|e| Error::new(ErrorKind::Other, e)).unwrap();
    let strtab = elf.strtab;

    for sym in elf.syms.iter() {
        if name == &strtab[sym.st_name] {
            return Some(RemotePtr::new((sym.st_value + la) as *mut c_void));
        }
    }
    None
}

