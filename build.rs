
use cc;

fn main() {
    cc::Build::new()
        .file("src/raw_syscall.S")
        .compile("my-asm-lib");
}
