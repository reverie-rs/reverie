
use std::fs::File;
use std::io::{Result, Write};
use std::path::Path;
use sysnum::gen_syscalls;

use cc;

fn gen_syscall_nrs() -> Result<()> {
    let dest_path = Path::new("src/syscall").join("nr.rs");
    let mut f = File::create(&dest_path)?;
    writeln!(f, "use self::SyscallNo::*;")?;
    writeln!(
        f,
        "#[allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]\n"
    )?;
    writeln!(f, "#[derive(Debug, Eq, PartialEq, Clone, Copy)]")?;
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

// FIXME: this introduces a source dependency on the systrace lib:
fn main() {
    gen_syscall_nrs().unwrap();
    cc::Build::new()
        .file("../../src/raw_syscall.S")
        .file("../../src/strlen.c")
        .file("src/init.c")
        .compile("my-asm-lib");
}
