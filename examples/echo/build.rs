
use cc;

fn main() {
    cc::Build::new()
        .define("_POSIX_C_SOURCE", "20180920")
        .define("_GNU_SOURCE", "1")
        .include("../../include")
        .include("../../trampoline")
        .file("../../trampoline/trampoline.S")
        .file("../../trampoline/raw_syscall.S")
        .file("../../trampoline/hook.c")
        .compile("trampoline");
    std::fs::copy("../../trampoline/ffi.rs", "src/ffi.rs").unwrap();
}
