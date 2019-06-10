use std::fs::File;
use std::io::{Result, Write};
use std::path::PathBuf;

use cc;

fn main() -> Result<()> {
    cc::Build::new()
        .flag("-D_GNU_SOURCE=1")
        .file("src/bpf_ll.c")
        .file("src/bpf-helper.c")
        .file("src/dl_ns.c")
        .compile("my-asm-lib");
    std::fs::copy("../src/consts.rs", "src/consts.rs")?;
    Ok(())
}
