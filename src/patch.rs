
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
use nix::unistd::Pid;
use nix::sys::{wait, signal, ptrace};
use libc;

use crate::hooks;
use crate::consts::*;
use crate::nr;

const SYSCALL_INSN_SIZE: usize = 2;

#[derive(Debug, Clone)]
pub struct ProcMapsEntry {
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
      choice([char('-'), char('s'), char('p')]),
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
        if p == 'p' {
            flags |= libc::MAP_PRIVATE;
        } else if p == 's' {
            flags |= libc::MAP_SHARED;
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

pub fn decode_proc_maps(pid: unistd::Pid) -> Result<Vec<ProcMapsEntry>> {
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

pub fn patch_at(pid: unistd::Pid, regs: libc::user_regs_struct, hook: &hooks::SyscallHook, target: u64) -> Result<()> {
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

// search for spare page(s) which can be allocated (mmap) within the
// range of @addr_hint +/- 2GB.
pub fn search_stub_page(pid: Pid, addr_hint: u64, pages: usize) -> Result<u64> {
    let mappings = decode_proc_maps(pid)?;
    let page_size: u64 = 0x1000;
    let one_mb: u64 = 0x100000;
    let almost_2gb: u64 = 2u64.wrapping_shl(30) - 0x100000;
    let mut ranges_from: Vec<(u64, u64)> = Vec::new();
    let mut ranges_to:Vec<(u64, u64)> = Vec::new();

    ranges_from.push((one_mb - page_size, one_mb));
    mappings.iter().for_each(|e|ranges_from.push((e.base, e.base+e.size)));
    mappings.iter().for_each(|e|ranges_to.push((e.base, e.base+e.size)));
    ranges_to.push((0xffffffff_ffff_8000u64, 0xffffffff_ffff_f000u64));
    debug_assert_eq!(ranges_from.len(), ranges_to.len());

    let res: Vec<u64> = ranges_from.iter().zip(ranges_to).filter_map(| ((x1, y1), (x2, y2)) | {
        let space = x2 - y1;
        let start_from = *y1;
        if space >= (pages as u64 * page_size) {
            if start_from <= addr_hint && start_from + almost_2gb >= addr_hint {
                Some(start_from)
            } else if start_from >= addr_hint && start_from - addr_hint <= almost_2gb - (pages as u64 * page_size) {
                Some(start_from)
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    match res.iter().next() {
        None => Err(Error::new(ErrorKind::Other, format!("cannot allocate stub page for {:x}", addr_hint))),
        Some(addr) => Ok(*addr),
    }
}

#[test]
fn can_find_stub_page() {
    let pid = unistd::getpid();
    let ranges: Vec<(u64, u64)> = decode_proc_maps(pid).unwrap().iter().map(|e|(e.base, e.base+e.size)).collect();
    let addr_hints: Vec<u64> = decode_proc_maps(pid).unwrap().iter().map(|e|e.base+0x234).collect();
    let two_gb = 2u64.wrapping_shl(30);
    for hint in addr_hints {
        let ret_ = search_stub_page(pid, hint, 1);
        assert!(ret_.is_ok());
        let ret = ret_.unwrap();
        println!("searching {:x} returned {:x}", hint, ret);
        if ret <= hint {
            assert!(hint - ret <= two_gb);
        } else {
            assert!(ret - hint <= two_gb);
        }
        let has_collision = ranges.iter().fold(false, | acc, (start, end) | {
            if acc {
                acc
            } else {
                ret >= *start && ret < *end
            }
        });
        assert!(!has_collision);
    }
}

pub fn gen_syscall_sequences_at(pid: Pid, page_address: u64) -> nix::Result<()> {
    /* the syscall sequences used here:
     * 0:   0f 05                   syscall 
     * 2:   c3                      retq                     // not filered by seccomp, untraced_syscall
     * 3:   90                      nop
     * 4:   0f 05                   syscall                  // traced syscall
     * 6:   c3                      retq   
     * 7:   90                      nop
     * 8:   e8 f3 ff ff ff          callq  0 <_do_syscall>   // untraced syscall, then breakpoint.
     * d:   cc                      int3   
     * e:   66 90                   xchg   %ax,%ax
     * 10:   e8 ef ff ff ff          callq  4 <_do_syscall+0x4> // traced syscall, then breakpoint
     * 15:   cc                      int3   
     * 16:   66 90                   xchg   %ax,%ax
     */
    let syscall_stub: &[u64] = &[ 0x90c3050f90c3050f,
                                  0xe8f7ffffffcc6690,
                                  0xe8efffffffcc6690
    ];
    // please note we force each `ptrace::write` to be exactly ptrace_poke (8 bytes a time)
    // instead of using `process_vm_writev`, because this function can be called in
    // PTRACE_EXEC_EVENT, the process seems not fully loaded by ld-linux.so
    // call process_vm_{readv, writev} would 100% fail.
    for (k, s) in syscall_stub.iter().enumerate() {
        let offset = k * std::mem::size_of::<u64>() + page_address as usize;
        ptrace::write(pid, offset as ptrace::AddressType, *s as *mut libc::c_void)?;
    }
    Ok(())
}
