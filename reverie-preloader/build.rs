use std::io;

use cc;

fn main() -> io::Result<()> {
    cc::Build::new()
        .flag("-D_GNU_SOURCE=1")
        .file("src/dl_ns.c")
        .compile("my-asm-lib");
    Ok(())
}
