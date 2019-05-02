
use cc;

fn main() {
    cc::Build::new()
        .flag("-Wall").flag("-fPIC").flag("-O2")
        .flag("-D_POSIX_C_SOURCE=20180920").flag("-D_GNU_SOURCE=1")
        .flag("-I../../include").flag("-I../../trampoline")
        .file("../../trampoline/trampoline.S")
        .file("../../trampoline/raw_syscall.S")
        .file("../../trampoline/route.c")
        .compile("my-trampoline-lib");
}
