
use cc;

fn main() {
    cc::Build::new()
        .file("../src/raw_syscall.S")
        .file("../src/strlen.c")
        .compile("my-asm-lib");
}
