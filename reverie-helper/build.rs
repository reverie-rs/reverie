use std::io::Result;

fn main() -> Result<()> {
    cc::Build::new()
        .define("_POSIX_C_SOURCE", "20180920")
        .define("_GNU_SOURCE", "1")
        .define("USE_SAVE", "1")
        .flag("-fPIC")
        .include("../include")
        .include("./src")
        .file("./src/trampoline.S")
        .file("./src/raw_syscall.S")
        .file("./src/remote_call.S")
        .compile("my-trampoline");

    Ok(())
}
