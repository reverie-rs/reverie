//! fcntl show helpers

use std::convert::TryFrom;
use core::fmt;
use crate::show::types::*;

macro_rules! fcntl_cmd_match_value {
    ($flag:ident, $value:ident) => {
        if $flag == FcntlCmd::$value as i32 {
            Ok(FcntlCmd::$value)
        } else {
            Err("BAD fcntl cmd")
        }
    };
}

/// fcntl cmd/arg
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
enum FcntlCmd {
    F_DUPFD = 0,
    F_GETFD = 1,
    F_SETFD = 2,
    F_GETFL = 3,
    F_SETFL = 4,
    F_GETLK = 5,
    F_SETLK = 6,
    F_SETLKW = 7,
    F_SETOWN = 8,
    F_GETOWN = 9,
    F_SETSIG = 10,
    F_GETSIG = 11,
    F_GETLK64 = 12,
    F_SETLK64 = 13,
    F_SETLKW64 = 14,
    F_SETOWN_EX = 15,
    F_GETOWN_EX = 16,
    F_GETOWNER_UIDS = 17,

    F_OFD_GETLK = 36,
    F_OFD_SETLK = 37,
    F_OFD_SETLKW = 38,

    F_SETLEASE = 1024,
    F_GETLEASE = 1025,
    F_NOTIFY = 1026,
    F_DUPFD_CLOEXEC = 1030,
    F_SETPIPE_SZ = 1031,
    F_GETPIPE_SZ = 1032,
    F_ADD_SEALS = 1033,
    F_GET_SEALS = 1034,
    F_GET_RW_HINT = 1035,
    F_SET_RW_HINT = 1036,
    F_GET_FILE_RW_HINT = 1037,
    F_SET_FILE_RW_HINT = 1038,
}

impl TryFrom<i32> for FcntlCmd {
    type Error = &'static str;
    fn try_from(cmd: i32) -> Result<Self, Self::Error> {
        fcntl_cmd_match_value!(cmd, F_DUPFD)
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETFD))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETFD))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETFL))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETFL))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETLK))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETLK))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETLKW))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETOWN))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETOWN))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETSIG))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETSIG))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETLK64))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETLK64))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETLKW64))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETOWN_EX))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETOWN_EX))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETOWNER_UIDS))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_OFD_GETLK))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_OFD_SETLK))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_OFD_SETLKW))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETLEASE))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETLEASE))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_NOTIFY))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_DUPFD_CLOEXEC))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SETPIPE_SZ))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GETPIPE_SZ))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_ADD_SEALS))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GET_SEALS))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GET_RW_HINT))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SET_RW_HINT))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_GET_FILE_RW_HINT))
            .or_else(|_| fcntl_cmd_match_value!(cmd, F_SET_FILE_RW_HINT))
    }
}

/// fcntl cmd/arg formatter
/// NB: only a few fcntl can be formatted correctly
pub fn fmt_fcntl(cmd: i32, arg: u64, f: &mut fmt::Formatter) -> fmt::Result {
    if let Ok(res) = FcntlCmd::try_from(cmd) {
        write!(f, "{:?}", res)?;
        match res {
            FcntlCmd::F_DUPFD | FcntlCmd::F_DUPFD_CLOEXEC | FcntlCmd::F_SETFD => {
                write!(f, ", {}", SyscallArg::Fd(arg as i32))?;
            }
            FcntlCmd::F_SETFL => {
                write!(f, ", {}", SyscallArg::FdFlags(arg as i32))?;
            }
            _ => {
                ;
            }
        }
        Ok(())
    } else {
        write!(f, "<BAD fcntl: {:#x}, {:#x}", cmd, arg)
    }
}
