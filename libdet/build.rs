
use std::fs::File;
use std::io::{Write, Result};
use std::path::Path;
use sysnr::gen_syscalls;

use cc;

fn gen_syscall_nrs() -> Result<()>{
    let dest_path = Path::new("src/syscall").join("nr.rs");
    let mut f = File::create(&dest_path)?;
    writeln!(f, "#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]\n")?;
    writeln!(f, "use self::SyscallNo::*;")?;

    writeln!(f, "#[derive(Debug, Eq, PartialEq, Clone)]")?;
    writeln!(f, "pub enum SyscallNo {{")?;
    let syscalls = gen_syscalls().unwrap();
    for (name, nr) in &syscalls {
        writeln!(f, "    SYS{} = {},", name.chars().skip(4).collect::<String>(), nr)?;
    }
    writeln!(f, "}}")?;

    writeln!(f, "static syscall_names: [&str; {}] = [", syscalls.len())?;
    for (name, _) in &syscalls {
        writeln!(f, "    \"{}\",", name.chars().skip(5).collect::<String>().as_str())?;
    }
    writeln!(f, "];")?;

    writeln!(f, "impl ToString for SyscallNo {{")?;
    writeln!(f, "  fn to_string(&self) -> String {{")?;
    writeln!(f, "    syscall_names[self.clone() as usize].to_string()")?;
    writeln!(f, "  }}")?;
    writeln!(f, "}}")?;

    writeln!(f, "static syscall_ids: [SyscallNo; {}] = [", syscalls.len())?;
    for (name, _) in &syscalls {
        writeln!(f, "    SYS{},", name.chars().skip(4).collect::<String>())?;
    }
    writeln!(f, "];")?;

    writeln!(f, "impl From<i32> for SyscallNo {{")?;
    writeln!(f, "  fn from(item: i32) -> Self {{")?;
    writeln!(f, "    if item as usize > syscall_ids.len() {{")?;
    writeln!(f, "      panic!(\"invalid syscall: {{}}\", item)")?;
    writeln!(f, "    }} else {{")?;
    writeln!(f, "      syscall_ids[item as usize].clone()")?;
    writeln!(f, "    }}")?;
    writeln!(f, "  }}")?;
    writeln!(f, "}}")?;

    Ok(())
}

fn main() {
    gen_syscall_nrs().unwrap();
    cc::Build::new()
        .file("../src/raw_syscall.S")
        .file("../src/strlen.c")
        .file("src/init.c")
        .compile("my-asm-lib");
}
