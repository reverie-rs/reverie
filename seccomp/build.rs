use std::fs::File;
use std::io::{Result, Write};
use std::path::PathBuf;

use cc;

fn main() -> Result<()> {
    cc::Build::new()
        .flag("-D_GNU_SOURCE=1")
        .file("src/bpf_ll.c")
        .file("src/bpf-helper.c")
        .compile("my-asm-lib");
    Ok(())
}
