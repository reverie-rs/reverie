use std::fs::File;
use std::io::{Result, Write};
use std::path::PathBuf;
use std::env;
use sysnum::gen_syscalls;
use std::process::Command;

use cc;

fn gen_syscall_nrs(dest: PathBuf) -> Result<()> {
    let mut f = File::create(dest)?;
    writeln!(f, "pub use self::SyscallNo::*;")?;

    writeln!(
        f,
        "#[allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]\n"
    )?;
    writeln!(f, "#[derive(Debug, PartialEq, Eq, Clone, Copy)]")?;
    writeln!(f, "pub enum SyscallNo {{")?;
    let syscalls = gen_syscalls().unwrap();
    for (name, nr) in &syscalls {
        writeln!(
            f,
            "    SYS{} = {},",
            name.chars().skip(4).collect::<String>(),
            nr
        )?;
    }
    writeln!(f, "}}")?;

    writeln!(f, "static SYSCALL_NAMES: [&str; {}] = [", syscalls.len())?;
    for (name, _) in &syscalls {
        writeln!(
            f,
            "    \"{}\",",
            name.chars().skip(5).collect::<String>().as_str()
        )?;
    }
    writeln!(f, "];")?;

    writeln!(f, "impl ToString for SyscallNo {{")?;
    writeln!(f, "    fn to_string(&self) -> String {{")?;
    writeln!(
        f,
        "        SYSCALL_NAMES[self.clone() as usize].to_string()"
    )?;
    writeln!(f, "    }}")?;
    writeln!(f, "}}")?;

    writeln!(f, "static SYSCALL_IDS: [SyscallNo; {}] = [", syscalls.len())?;
    for (name, _) in &syscalls {
        writeln!(f, "    SYS{},", name.chars().skip(4).collect::<String>())?;
    }
    writeln!(f, "];")?;

    writeln!(f, "impl From<i32> for SyscallNo {{")?;
    writeln!(f, "    fn from(item: i32) -> Self {{")?;
    writeln!(f, "        if item as usize > SYSCALL_IDS.len() {{")?;
    writeln!(f, "            panic!(\"invalid syscall: {{}}\", item)")?;
    writeln!(f, "        }} else {{")?;
    writeln!(f, "            SYSCALL_IDS[item as usize]")?;
    writeln!(f, "        }}")?;
    writeln!(f, "    }}")?;
    writeln!(f, "}}")?;

    Ok(())
}

// build `libtrampoline.so`
// not using GNU make because this is a lot easier
// than figureing out how to use variable rules (LHS) in makefile
fn build_trampoline(){
    let mut cc = Command::new(env::var("CC").unwrap_or(String::from("cc")));
    let srcs = &[ "trampoline.S", "raw_syscall.S", "route.c" ];
    let output = PathBuf::from("target")
        .join(env::var("PROFILE").unwrap())
        .join("libsystrace-trampoline.so");
    srcs.iter().for_each(|src| {
        let path = PathBuf::from("trampoline").join(src);
        cc.arg(path);
    });
    cc.arg("-o").arg(output);
    cc.args(&[ "-g", "-Wall", "-fPIC", "-O2", "-D_POSIX_C_SOURCE=20180920",
                 "-D_GNU_SOURCE=1", "-Iinclude", "-Itrampoline" ]);
    cc.args(&[ "-nostdlib", "-shared", "-Wl,--no-as-needed"]);
    println!("[build.rs] invoking: {:?}", cc);
    cc.status().expect("failed to build libtrampoline.so");
}

fn main() {
    build_trampoline();
    gen_syscall_nrs(PathBuf::from("src").join("nr.rs")).unwrap();
    cc::Build::new()
        .file("src/bpf.c")
        .file("src/bpf-helper.c")
        .compile("my-asm-lib");
}
