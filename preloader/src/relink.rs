//! relink

use std::collections::HashMap;
use std::ptr::NonNull;
use procfs::MemoryMap;
use std::path::PathBuf;
use procfs;
use nix::unistd;

/// `link_map` from link.h re-exported by glibc
/// note this is not the full-blown version
#[derive(Debug)]
pub struct LinkMap {
    pub name: PathBuf,
    pub ranges: Vec<MemoryMap>,
    dynamic: HashMap<u64, u64>,
}

impl LinkMap {
    pub fn load_address(&self) -> Option<u64> {
        if self.ranges.len() < 1 {
            None
        } else {
            Some(self.ranges[0].address.0)
        }
    }
}

extern "C" {
    fn _early_preload_dso(dso: *const i8) -> *mut core::ffi::c_void;
}

#[repr(C)]
struct ll_link_map {
    l_addr: u64,
    l_name: *const i8,
    l_ld: u64,
    l_next: u64,
    l_prev: u64,
}

fn into_ranges(maps: &Vec<MemoryMap>, base: u64, name: &PathBuf) -> Vec<MemoryMap> {
    maps.iter().skip_while(|e| e.address.0 != base).take_while(|e| {
        match &e.pathname {
            procfs::MMapPath::Path(p) => {
                p == name
            }
            _ => false,
        }
    }).cloned().collect()
}

pub fn dl_open_ns(dso: &str) -> Vec<LinkMap> {
    let pid = unistd::getpid();
    let mut res: Vec<LinkMap> = Vec::new();
    let handle = unsafe {
        let dso_ = String::from(dso) + "\0";
        _early_preload_dso(dso_.as_ptr() as *const i8)
    };
    let head = std::ptr::NonNull::new(handle as *mut ll_link_map);
    let maps = procfs::Process::new(pid.as_raw()).and_then(|p| {
        p.maps()
    }).unwrap();

    let mut _curr = head.clone();
    
    while let Some(curr) = _curr {
        let ll = unsafe {
            std::ptr::read(curr.as_ptr())
        };

        let name = unsafe {
            std::ffi::CStr::from_ptr(ll.l_name).to_str().unwrap()
        };
        let p = std::fs::canonicalize(name).unwrap_or_else(|_|PathBuf::from(name));
        let entry = LinkMap {
            ranges: into_ranges(&maps, ll.l_addr, &p),
            name: p,
            dynamic: HashMap::new(),
        };
        res.push(entry);
        _curr = NonNull::new(ll.l_next as *mut ll_link_map);
    }

    res
}
