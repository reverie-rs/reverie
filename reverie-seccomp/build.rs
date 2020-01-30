use cc;
use std::io;

fn main() -> io::Result<()> {
    cc::Build::new()
        .flag("-D_GNU_SOURCE=1")
        .flag("-std=c99")
        .file("src/bpf_ll.c")
        .file("src/bpf-helper.c")
        .compile("my-asm-lib");
    Ok(())
}
