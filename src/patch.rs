
use std::io::{Error, ErrorKind, Result, Read};
use std::result;
use std::fs::File;
use std::path::PathBuf;

use combine::error::ParseError;
use combine::Parser;
use combine::{many, many1, any, optional, none_of, choice, Stream, count};
use combine::stream::state::State;
use combine::parser::char::{digit, hex_digit, letter, char, spaces};

use nix::unistd;
use nix::sys::{wait, signal, ptrace};
use libc;

use crate::hooks;
use crate::consts::*;
use crate::nr;

const SYSCALL_INSN_SIZE: usize = 2;

#[derive(Debug, Clone)]
struct ProcMapsEntry {
    base: u64,
    size: u64,
    prot: i32,
    flags: i32,
    offset: u64,
    dev: i32,
    inode: u64,
    file: Option<PathBuf>,
}

fn hex_value<I>() -> impl Parser<Input = I, Output = u64>
where
    I: Stream<Item = char>,
    // Necessary due to rust-lang/rust#24159
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    many1::<String, _>(hex_digit()).map(|s| u64::from_str_radix(&s, 16).unwrap())
}

fn dec_value<I>() -> impl Parser<Input = I, Output = u64>
where
    I: Stream<Item = char>,
    // Necessary due to rust-lang/rust#24159
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    many1::<String, _>(hex_digit()).map(|s| s.parse::<u64>().unwrap())
}

fn dev<I>() -> impl Parser<Input = I, Output = i32>
where
    I: Stream<Item = char>,
    // Necessary due to rust-lang/rust#24159
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    ( spaces(),
      count::<String,_>(2,hex_digit()),
      char(':'),
      count::<String,_>(2,hex_digit()),
    ).map(|(_, major, _, minor)| {
        i32::from_str_radix(&major, 16).unwrap() * 256
            + i32::from_str_radix(&minor, 16).unwrap()
    })
}

fn prot<I>() -> impl Parser<Input = I, Output = (i32, i32)>
where
    I: Stream<Item = char>,
    // Necessary due to rust-lang/rust#24159
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    ( spaces(),
      choice([char('-'), char('r')]),
      choice([char('-'), char('w')]),
      choice([char('-'), char('x')]),
      choice([char('-'), char('p')]),
    ).map(|(_, r, w, x, p)| {
        let mut prot: i32 = 0;
        let mut flags: i32 = 0;
        if r == 'r' {
            prot |= libc::PROT_READ;
        }
        if w == 'w' {
            prot |= libc::PROT_WRITE;
        }
        if x == 'x' {
            prot |= libc::PROT_EXEC;
        }
        if p == '[' {
            flags |= libc::MAP_PRIVATE;
        }
        (prot, flags)
    })
}

fn filepath<I>() -> impl Parser<Input = I, Output = Option<PathBuf>>
where
    I: Stream<Item = char>,
    // Necessary due to rust-lang/rust#24159
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    ( spaces(),
      optional(many1::<String,_>(none_of("\r\n".chars().into_iter())))
    ).map(|(_, path)| path.map(|s| PathBuf::from(s)))
}

fn parse_proc_maps_entry(line: &str) -> Result<ProcMapsEntry> {
    match parser().easy_parse(line) {
        Ok((result, _)) => Ok(result),
        Err(parse_error) => Err(Error::new(ErrorKind::Other, format!("parse error: {}", parse_error))),
    }
}

fn parser<I>() -> impl Parser<Input = I, Output = ProcMapsEntry>
where
    I: Stream<Item = char>,
    // Necessary due to rust-lang/rust#24159
    I::Error: ParseError<I::Item, I::Range, I::Position>,
{
    ( hex_value(),
      char('-'),
      hex_value(),
      prot(),
      spaces(),
      hex_value(),
      dev(),
      spaces(),
      dec_value(),
      filepath()
    ).map(|(from, _, to, (prot_val, flags_val), _, offset, devno, _, inode, path)| {
        ProcMapsEntry{
            base: from,
            size: to - from,
            prot: prot_val,
            flags: flags_val,
            offset,
            dev: devno,
            inode,
            file: path}
    })
}

fn decode_proc_maps(pid: unistd::Pid) -> Result<Vec<ProcMapsEntry>> {
    let filepath = PathBuf::from("/proc").join(&format!("{}", pid)).join(PathBuf::from("maps"));
    let mut file = File::open(filepath)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let ents: Vec<Result<_>> = contents.lines().map(|line| parse_proc_maps_entry(line)).collect();
    ents.into_iter().collect()
}

#[test]
fn can_decode_proc_self_maps() -> Result<()> {
    let my_pid = unistd::getpid();
    let decoded = decode_proc_maps(my_pid)?;
    assert!(decoded.len() > 0);
    Ok(())
}

pub fn libsystrace_load_address(pid: unistd::Pid) -> Result<u64>{
    let decoded = decode_proc_maps(pid)?;
    let mut it = decoded.iter().filter(|e| e.file.clone().map(|s| s.ends_with(SYSTRACE_SO)).unwrap_or(false));
    match it.next() {
        Some(e) => Ok(e.base),
        None => Err(Error::new(ErrorKind::Other, format!("cannot find {} from tracee (pid={})", SYSTRACE_SO, pid))),
    }
}

fn ensure_syscall(pid: unistd::Pid, rip: u64) -> Result<()> {
    let insn = ptrace::read(pid, rip as ptrace::AddressType).expect("ptrace peek failed") as u64;
    match insn & SYSCALL_INSN_MASK as u64 {
        SYSCALL_INSN => Ok(()),
        _otherwise => Err(Error::new(ErrorKind::Other, format!("expect syscall instructions at {:x}, but got: {:x}", rip, insn))),
    }
}

pub fn pretty_show_maps(pid: unistd::Pid) -> String {
    let mut res = String::new();

    let ents = decode_proc_maps(pid).unwrap();

    for e in ents {
        let s = format!("{:x?}\n", e);
        res.push_str(&s);
    }
    res
}

pub fn may_patch_syscall_from(pid: unistd::Pid, syscall: nr::SyscallNo, regs: libc::user_regs_struct, hooks: &Vec<hooks::SyscallHook>, la: u64) -> Result<()> {
    ensure_syscall(pid, regs.rip - SYSCALL_INSN_SIZE as u64)?;

    let mut bytes: Vec<u8> = Vec::new();

    for i in 0..=1 {
        let u64_size = std::mem::size_of::<u64>();
        let u: u64 = ptrace::read(pid, (regs.rip + i * u64_size as u64) as ptrace::AddressType).expect("ptrace peek failed") as u64;
        let raw: [u8; std::mem::size_of::<u64>()]  = unsafe { std::mem::transmute(u) };
        raw.iter().for_each(|c| bytes.push(*c));
    }

    let mut it = hooks.iter().filter(|hook| {
        let sequence: &[u8] = &bytes[0..hook.instructions.len()];
        sequence == hook.instructions.as_slice()
    });
    match it.next() {
        None        => {
            // print!("{}", pretty_show_maps(pid));
            println!("unpatchable syscall {:?} at {:x}, instructions: {:x?}", syscall, regs.rip, bytes);
            Ok(())
            //Err(Error::new(ErrorKind::Other, format!("unpatchable syscall {:?} at {:x}, instructions: {:x?}", syscall, regs.rip, bytes)))
        },
        Some(found) => {
            let jump_target = found.offset + la;
            patch_at(pid, regs, found, jump_target)
        },
    }
}

// so here we are, at ptrace seccomp stop, if we simply resume, the kernel would
// do the syscall, without our patch. we change to syscall number to -1, so that
// kernel would simply skip the syscall, so that we can jump to our patched syscall
// on the first run.
fn skip_seccomp_syscall(pid: unistd::Pid, regs: &libc::user_regs_struct) -> Result<()> {
    let mut new_regs = regs.clone();
    new_regs.orig_rax = -1i64 as u64;
    ptrace::setregs(pid, new_regs).expect("ptrace setregs failed");
    ptrace::step(pid, None).expect("ptrace single step");
    assert!(wait::waitpid(Some(pid), None) == Ok(wait::WaitStatus::Stopped(pid, signal::SIGTRAP)));
    Ok(())
}

fn synchronize_from(pid: unistd::Pid, rip: u64){
    let saved_insn = ptrace::read(pid, rip as ptrace::AddressType).expect("ptrace peek");
    let new_insn = (saved_insn & !0xff) | 0xcc;
    ptrace::write(pid, rip as ptrace::AddressType, new_insn as *mut libc::c_void).expect("ptrace poke");
    ptrace::cont(pid, None).expect("ptrace cont");
    assert!(wait::waitpid(Some(pid), None) == Ok(wait::WaitStatus::Stopped(pid, signal::SIGTRAP)));
    let mut regs = ptrace::getregs(pid).expect("ptrace getregs");
    regs.rip -= 1;
    ptrace::write(pid, rip as ptrace::AddressType, saved_insn as *mut libc::c_void).expect("ptrace poke");
    ptrace::setregs(pid, regs).expect("ptrace setregs");
}

fn patch_at(pid: unistd::Pid, regs: libc::user_regs_struct, hook: &hooks::SyscallHook, target: u64) -> Result<()> {
    let resume_from = regs.rip - SYSCALL_INSN_SIZE as u64;
    let jmp_insn_size = 5;
    let ip = resume_from;
    
    let rela: i64 = target as i64 - ip as i64 - jmp_insn_size as i64;
    assert!(rela >= -1i64.wrapping_shl(31) && rela < 1i64.wrapping_shl(31));

    let mut insn_at_syscall = ptrace::read(pid, ip as ptrace::AddressType).expect("ptrace peek failed") as u64;
    // set LSB-40bit to a callq/jmp instruction.
    insn_at_syscall &= !(0xff_ffffffffu64);
    insn_at_syscall |=    0xe8u64
                        | (rela as u64 & 0xff).wrapping_shl(8)
                        | (rela as u64 & 0xff00).wrapping_shl(8)
                        | (rela as u64 & 0xff0000).wrapping_shl(8)
                        | (rela as u64 & 0xff000000).wrapping_shl(8);

    skip_seccomp_syscall(pid, &regs)?;

    ptrace::write(pid, ip as ptrace::AddressType, insn_at_syscall as *mut libc::c_void).expect("ptrace poke failed");

    let padding_size = SYSCALL_INSN_SIZE + hook.instructions.len() - jmp_insn_size as usize;
    assert!(padding_size <= 9);

    let nops: Vec<(usize, u64)> = vec![
        (0, 0x0),
        (1, 0x90),
        (2, 0x9066),
        (3, 0x001f0f),
        (4, 0x00401f0f),
        (5, 0x0000441f0f),
        (6, 0x0000441f0f66),
        (7, 0x00000000801f0f),
        (8, 0x0000000000841f0f),
        (9, 0x0000000000841f0f66),
    ];
    let masks: Vec<u64> = vec![0x0u64, 0xffu64, 0xffffu64, 0xffffffu64, 0xffffffffu64,
                               0xff_ffffffffu64, 0xffff_ffffffffu64,
                               0xffffff_ffffffffu64, 0xffffffff_ffffffffu64];
    if padding_size == 0 {
        ;
    } else if padding_size <= 8 {
        let insn_after_patch = ip + jmp_insn_size;
        let mut padding_insn = ptrace::read(pid, insn_after_patch as ptrace::AddressType).expect("ptrace peek") as u64;
        padding_insn &= !(masks[padding_size]);
        padding_insn |= nops[padding_size].1;
        ptrace::write(pid, insn_after_patch as ptrace::AddressType, padding_insn as *mut libc::c_void).expect("ptrace poke");
    } else if padding_size == 9 {
        let insn_after_patch = ip + jmp_insn_size;
        let insn_after_patch_2 = insn_after_patch + std::mem::size_of::<u64>() as u64;
        ptrace::write(pid, insn_after_patch as ptrace::AddressType, nops[padding_size].1 as *mut libc::c_void).expect("ptrace poke");
        ;
        let mut insn2 = ptrace::read(pid, insn_after_patch_2 as ptrace::AddressType).expect("ptrace peek") as u64;
        insn2 &= !0xff;  // the last byte of the 9-byte nop is 0x00.
        ptrace::write(pid, insn_after_patch as ptrace::AddressType, insn2 as *mut libc::c_void).expect("ptrace poke");
    } else {
        panic!("maximum padding is 9");
    }

    let mut new_regs = regs.clone();
    new_regs.rax = regs.orig_rax; // for our patch, we use rax as syscall no.
    new_regs.rip = ip; // rewind pc back (-2).
    ptrace::setregs(pid, new_regs).expect("ptrace setregs");

    // because we modified tracee's code
    // we need some kind of synchronization to make sure
    // the CPU (especially i-cache) noticed the change
    // hence we set a breakponit at ip (original rip - 2)
    // to force synchronization.
    synchronize_from(pid, ip);
    Ok(())
}

