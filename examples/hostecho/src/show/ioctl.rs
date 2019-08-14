//! ioctl show helpers

use std::convert::TryFrom;
use core::fmt;
use std::collections::HashMap;
use nix::unistd::Pid;

/// ioctl requests: only a subset is defined
#[derive(Clone, Copy, Debug)]
enum IoctlRequest {
    /* termios */
    TCGETS = 0x5401,
    TCSETS = 0x5402,
    TCSETSW = 0x5403,
    TCSETF = 0x5404,
    TCGETA = 0x5405,
    TCSETA = 0x5406,
    TCSETAW = 0x5407,

    TCSETAF = 0x5408,
    TCSBRK = 0x5409,
    TCXONC = 0x540a,
    TCFLSH = 0x540b,
    TIOCEXCL = 0x540c,
    TIOCNXCL = 0x540d,
    TIOCSCTTY = 0x540e,
    TIOCGPGRP = 0x540f,
    TIOCSPGRP = 0x5410,
    TIOCOUTQ = 0x5411,
    TIOCSTI = 0x5412,
    TIOCGWINSZ = 0x5413,
    TIOCSWINSZ = 0x5414,
    TIOCMGET = 0x5415,
    TIOCMBIS = 0x5416,
    TIOCMBIC = 0x5417,
    TIOCMSET = 0x5418,
    TIOCGSOFTCAR = 0x5419,
    TIOCSSOFTCAR = 0x541a,
    FIONREAD = 0x541b,
    TIOCLINUX = 0x541c,
    TIOCCONS = 0x541d,
    TIOCGSERIAL = 0x541e,
    TIOCSSERIAL = 0x541f,
    TIOCPKT = 0x5420,
    FIONBIO = 0x5421,
    TIOCNOTTY = 0x5422,
    TIOCSETD = 0x5423,
    TIOCGETD = 0x5424,
    TCSBRKP = 0x5425,
    TIOCTTYGSTRUCT = 0x5426,
    FIONCLEX = 0x5450,
    FIOCLEX = 0x5451,
    FIOASYNC = 0x5452,
    TIOCSERCONFIG = 0x5453,
    TIOCSERGWILD = 0x5454,
    TIOCSERSWILD = 0x5455,
    TIOCGLCKTRMIOS = 0x5456,
    TIOCSLCKTRMIOS = 0x5457,
    TIOCSERGSTRUCT = 0x5458,
    TIOCSERGETLSR = 0x5459,
    TIOCSERGETMULTI = 0x545a,
    TIOCSERSETMULTI = 0x545b,

    // more to follow
}

macro_rules! ioctl_make_tuple {
    ($t: ident) => {
        (IoctlRequest::$t as i32, IoctlRequest::$t)
    }
}

const _IOCTL_LIST: &[(i32, IoctlRequest)] = &[
    ioctl_make_tuple!(TCGETS),
    ioctl_make_tuple!(TCSETS),
    ioctl_make_tuple!(TCSETSW),
    ioctl_make_tuple!(TCSETF),
    ioctl_make_tuple!(TCGETA),
    ioctl_make_tuple!(TCSETA),
    ioctl_make_tuple!(TCSETAW),
    ioctl_make_tuple!(TCSETAF),
    ioctl_make_tuple!(TCSBRK),
    ioctl_make_tuple!(TCXONC),
    ioctl_make_tuple!(TCFLSH),
    ioctl_make_tuple!(TIOCEXCL),
    ioctl_make_tuple!(TIOCNXCL),
    ioctl_make_tuple!(TIOCSCTTY),
    ioctl_make_tuple!(TIOCGPGRP),
    ioctl_make_tuple!(TIOCSPGRP),
    ioctl_make_tuple!(TIOCOUTQ),
    ioctl_make_tuple!(TIOCSTI),
    ioctl_make_tuple!(TIOCGWINSZ),
    ioctl_make_tuple!(TIOCSWINSZ),
    ioctl_make_tuple!(TIOCMGET),
    ioctl_make_tuple!(TIOCMBIS),
    ioctl_make_tuple!(TIOCMBIC),
    ioctl_make_tuple!(TIOCMSET),
    ioctl_make_tuple!(TIOCGSOFTCAR),
    ioctl_make_tuple!(TIOCSSOFTCAR),
    ioctl_make_tuple!(FIONREAD),
    ioctl_make_tuple!(TIOCLINUX),
    ioctl_make_tuple!(TIOCCONS),
    ioctl_make_tuple!(TIOCGSERIAL),
    ioctl_make_tuple!(TIOCSSERIAL),
    ioctl_make_tuple!(TIOCPKT),
    ioctl_make_tuple!(FIONBIO),
    ioctl_make_tuple!(TIOCNOTTY),
    ioctl_make_tuple!(TIOCSETD),
    ioctl_make_tuple!(TIOCGETD),
    ioctl_make_tuple!(TCSBRKP),
    ioctl_make_tuple!(TIOCTTYGSTRUCT),
    ioctl_make_tuple!(FIONCLEX),
    ioctl_make_tuple!(FIOCLEX),
    ioctl_make_tuple!(FIOASYNC),
    ioctl_make_tuple!(TIOCSERCONFIG),
    ioctl_make_tuple!(TIOCSERGWILD),
    ioctl_make_tuple!(TIOCSERSWILD),
    ioctl_make_tuple!(TIOCGLCKTRMIOS),
    ioctl_make_tuple!(TIOCSLCKTRMIOS),
    ioctl_make_tuple!(TIOCSERGSTRUCT),
    ioctl_make_tuple!(TIOCSERGETLSR),
    ioctl_make_tuple!(TIOCSERGETMULTI),
    ioctl_make_tuple!(TIOCSERSETMULTI),
];

lazy_static! {
    static ref IOCTL_LIST: HashMap<i32, IoctlRequest> = {
        _IOCTL_LIST.iter().cloned().collect()
    };
}

impl TryFrom<i32> for IoctlRequest {
    type Error = &'static str;
    fn try_from(request: i32) -> Result<Self, Self::Error> {
        if let Some(found) = IOCTL_LIST.get(&request) {
            Ok(*found)
        } else {
            Err("Unknown ioctl value")
        }
    }
}

/// ioctl request/arg formatter
pub fn fmt_ioctl(_pid: Pid, request: i32, arg: u64, f: &mut fmt::Formatter) -> fmt::Result {
    match IoctlRequest::try_from(request) {
        Err(_)  => write!(f, "unknown ioctl {:#x}, {:#X}", request, arg),
        Ok(req) => write!(f, "{:?}, {:#x}", req, arg),
    }
}
