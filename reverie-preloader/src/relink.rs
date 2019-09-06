//! load dynamic shared object (tool) into a new linker namespace
//! the tool library and its dependencies thus will be isolated
//! into a different linker namespace.

use nix::unistd;
use procfs;
use procfs::MemoryMap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::ptr::NonNull;

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

fn into_ranges(
    maps: &Vec<MemoryMap>,
    base: u64,
    name: &PathBuf,
) -> Vec<MemoryMap> {
    maps.iter()
        .skip_while(|e| e.address.0 != base)
        .take_while(|e| match &e.pathname {
            procfs::MMapPath::Path(p) => p == name,
            _ => false,
        })
        .cloned()
        .collect()
}

/// `dl_open_ns`: load dynamic shared library into a new linker namespace
/// for more details, see: https://sourceware.org/glibc/wiki/LinkerNamespaces
pub fn dl_open_ns(dso: String) -> Vec<LinkMap> {
    let handle = unsafe {
        // make sure dso is null terminated without calling malloc
        let path = dso + "\0";
        _early_preload_dso(path.as_ptr() as *const i8)
    };

    // after `dlmopen` successed, malloc/free points to the new
    // implementation and we're safe to use them
    let pid = unistd::getpid();
    let mut res: Vec<LinkMap> = Vec::new();

    let head = std::ptr::NonNull::new(handle as *mut ll_link_map);
    let maps = procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .unwrap();

    let mut _curr = head.clone();

    while let Some(curr) = _curr {
        let ll = unsafe { std::ptr::read(curr.as_ptr()) };

        let name =
            unsafe { std::ffi::CStr::from_ptr(ll.l_name).to_str().unwrap() };
        let p =
            std::fs::canonicalize(name).unwrap_or_else(|_| PathBuf::from(name));
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
