use std::io::{Result};

use cc;

fn main() -> Result<()> {
    cc::Build::new()
        .flag("-D_GNU_SOURCE=1")
        .file("src/dl_ns.c")
        .compile("my-asm-lib");
    std::fs::copy("../src/consts.rs", "src/consts.rs")?;
    Ok(())
}
