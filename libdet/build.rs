
use cc;

use std::fs::File;
use std::io::Write;
use std::path::Path;
use sysnr::gen_syscalls;

fn gen_syscall_nrs() {
    let dest_path = Path::new("src/syscall").join("nr.rs");
    let mut f = File::create(&dest_path).unwrap();

    writeln!(f, "#![allow(non_upper_case_globals)]").unwrap();
    for (name, nr) in gen_syscalls().unwrap() {
        writeln!(f, "pub const SYS{}: i32 = {};", name.chars().skip(4).collect::<String>(), nr).unwrap();
    }
}

fn main() {
    gen_syscall_nrs();
    cc::Build::new()
        .file("../src/raw_syscall.S")
        .file("../src/strlen.c")
        .compile("my-asm-lib");
}
