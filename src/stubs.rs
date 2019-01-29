
use std::io::{Result, Write, Error, ErrorKind};
use std::fs::File;
use std::path::PathBuf;
use nix::unistd;
use nix::unistd::Pid;

use crate::patch;
use crate::hooks;
use crate::consts;

// jmp *0x0(pc)
// .qword offset_64bit.
const X64_JUMP_ABS_PC_RELA: &[u8] = &[0xff,0x25, 0x00, 0x00, 0x00, 0x00];

fn gen_extended_jump(jump_address: u64) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();

    X64_JUMP_ABS_PC_RELA.iter().for_each(|c|res.push(*c));

    res.push( (jump_address.wrapping_shr(0) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(8) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(16) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(24) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(32) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(40) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(48) & 0xff) as u8);
    res.push( (jump_address.wrapping_shr(56) & 0xff) as u8);

    debug_assert_eq!(res.len(), 14);

    res
}

#[test]
fn extend_jump_sanity() {
    let expected_size = X64_JUMP_ABS_PC_RELA.len() + std::mem::size_of::<u64>();
    assert_eq!(gen_extended_jump(0x0).len(), expected_size);
    assert_eq!(gen_extended_jump(0x12345678).len(), expected_size);
    assert_eq!(gen_extended_jump(0x1234567812345678u64).len(), expected_size);
}

pub fn extended_jump_size() -> usize {
    0x80
}

// 2*4096 / 128 => 64
pub fn extended_jump_pages() -> usize {
    2
}

pub fn gen_extended_jump_stubs(hooks: &Vec<hooks::SyscallHook>, addr: u64) -> Vec<u8> {
    let mut res :Vec<u8> = Vec::new();
    hooks.iter().for_each(|hook| {
        assert!(hook.instructions.len() <= extended_jump_size());
        let mut stub = gen_extended_jump(hook.offset + addr);
        let pad = extended_jump_size() - stub.len();
        res.append(&mut stub);
        for _i in 0..pad {
            res.push(0);
        }
        debug_assert!(res.len() % extended_jump_size() == 0);
    });
    res
}
