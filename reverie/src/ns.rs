use nix::{mount, unistd};
use std::fs::File;
use std::io::{Result, Write};
use std::path::PathBuf;

fn proc_setpgroups_write(child_pid: unistd::Pid) -> Result<()> {
    let setgroups = PathBuf::from("/proc")
        .join(&format!("{}", child_pid))
        .join(PathBuf::from("setgroups"));
    let mut file = File::create(setgroups)?;
    file.write_all(b"deny")?;
    Ok(())
}

fn update_map(
    starting_pid: unistd::Pid,
    starting_uid: unistd::Uid,
    starting_gid: unistd::Gid,
) -> Result<()> {
    let uid_map_file = PathBuf::from("/proc")
        .join(&format!("{}", starting_pid))
        .join(PathBuf::from("uid_map"));
    let gid_map_file = PathBuf::from("/proc")
        .join(&format!("{}", starting_pid))
        .join(PathBuf::from("gid_map"));
    let uid_map = &format!("0 {} 1", starting_uid);
    let gid_map = &format!("0 {} 1", starting_gid);

    for (p, s) in &[(uid_map_file, uid_map), (gid_map_file, gid_map)] {
        let mut file = File::create(p)?;
        file.write_all(s.as_bytes())?;
    }

    Ok(())
}

pub fn init_ns(
    starting_pid: unistd::Pid,
    starting_uid: unistd::Uid,
    starting_gid: unistd::Gid,
) -> Result<()> {
    proc_setpgroups_write(starting_pid)?;
    update_map(starting_pid, starting_uid, starting_gid)?;
    let source: Option<&PathBuf> = None;
    let target: PathBuf = PathBuf::from("/proc");
    let fstype: &str = "proc";
    let flags = mount::MsFlags::MS_MGC_VAL;
    let data: Option<&PathBuf> = None;
    mount::mount(source, &target, Some(fstype), flags, data)
        .expect("mount proc failed");
    Ok(())
}
