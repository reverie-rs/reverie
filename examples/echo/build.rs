
use cc;

fn main() {
    cc::Build::new()
        .define("_POSIX_C_SOURCE", "20180920")
        .define("_GNU_SOURCE", "1")
        .define("USE_SAVE", "1")
        .flag("-fPIC")
        .include("../../include")
        .include("../../trampoline")
        .file("../../trampoline/trampoline.S")
        .file("../../trampoline/raw_syscall.S")
        .file("../../trampoline/remote_call.S")
        .compile("my-trampoline");
    std::fs::copy("../../trampoline/ffi.rs", "src/ffi.rs").unwrap();
}
