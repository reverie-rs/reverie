
use cc;

fn main() {
    cc::Build::new()
        .file("src/init.c")
        .compile("my-asm-lib");
}
