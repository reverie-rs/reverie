/// accessing Linux perf events

use std::default::Default;
use nix::unistd::Pid;
use bitfield::*;

#[repr(C)]
pub union perf_sample {
    sample_period: u64,
    sample_freq: u64,
}
impl Default for perf_sample {
    fn default() -> Self {
        perf_sample {
            sample_period: 0
        }
    }
}

#[repr(C)]
pub union perf_wakeup {
    wakeup_events: u32,
    wakeup_watermark: u32,
}

impl Default for perf_wakeup {
    fn default() -> Self {
        perf_wakeup {
            wakeup_events: 0
        }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct perf_bp {
    pub bp_addr: u64,
    pub bp_len: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct perf_config {
    pub config1: u64,
    pub config2: u64,
}

#[repr(C)]
pub union perf_bp_config {
    bp: perf_bp,
    config: perf_config,
}

impl Default for perf_bp_config {
    fn default() -> Self {
        perf_bp_config {
            bp: Default::default()
        }
    }
}

bitfield! {
    #[allow(non_camel_case_types)]
    pub struct perf_event_bitfields(u64);
    impl Debug;
    pub disabled, set_disabled       : 0;   /* off by default */
    pub inherit, set_inherit        : 1;   /* children inherit it */
    pub pinned, set_pinned         : 2;   /* must always be on PMU */
    pub exclusive, set_exclusive      : 3;   /* only group on PMU */
    pub exclude_user, set_exclude_user   : 4;   /* don't count user */
    pub exclude_kernel, set_exclude_kernel : 5;   /* don't count kernel */
    pub exclude_hv, set_exclude_hv     : 6;   /* don't count hypervisor */
    pub exclude_idle, set_exclude_idle   : 7;   /* don't count when idle */
    pub mmap, set_mmap           : 8;   /* include mmap data */
    pub comm, set_comm           : 9;   /* include comm data */
    pub freq, set_freq           : 10;   /* use freq, not period */
    pub inherit_stat, set_inherit_stat   : 11;   /* per task counts */
    pub enable_on_exec, set_enable_on_exec : 12;   /* next exec enables */
    pub task, set_task           : 13;   /* trace fork/exit */
    pub watermark, set_watermark      : 14;   /* wakeup_watermark */
    pub precise_ip, set_precise_ip     : 16, 15;   /* skid constraint */
    pub mmap_data, set_mmap_data      : 17;   /* non-exec mmap data */
    pub sample_id_all, set_sample_id_all  : 18;   /* sample_type all events */
    pub exclude_host, set_exclude_host   : 19;   /* don't count in host */
    pub exclude_guest, set_exclude_guest  : 20;   /* don't count in guest */
    pub exclude_callchain_kernel, set_exclude_callchain_kernel : 21;
    /* exclude kernel callchains */
    pub exclude_callchain_user, set_exclude_callchain_user   : 22;
    /* exclude user callchains */
    pub mmap2, set_mmap2          :  23;  /* include mmap with inode data */
    pub comm_exec, _      :  24;  /* flag comm events that are
    due to exec */
    pub use_clockid, set_use_clockid    :  25;  /* use clockid for time fields */
    pub context_switch, set_context_switch :  26;  /* context switch data */

    __reserved_1, _   : 63, 27;
}

impl Default for perf_event_bitfields {
    fn default() -> Self {
        let r: perf_event_bitfields = unsafe {
            std::mem::transmute_copy(&0u64)
        };
        r
    }
}

#[test]
fn perf_event_bitfields_test() {
    let mut x: perf_event_bitfields = Default::default();
    x.set_context_switch(true);
    assert_eq!(x.context_switch(), true);
    assert_eq!(x.comm_exec(), false);
}

#[test]
fn perf_event_attr_sanity() {
    assert_eq!(std::mem::size_of::<perf_event_attr>(), 112);
}

#[repr(C)]
#[derive(Default)]
pub struct perf_event_attr {
    event_type: u32,
    event_size: u32,
    config: u64,
    sample: perf_sample,
    sample_type: u64,
    read_format: u64,
    event_control: perf_event_bitfields,
    wakeup_type: perf_wakeup,
    bp_type: u32,
    bp_config: perf_bp_config,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
}

pub const PERF_EVENT_IOC_ENABLE: u64 = 9216u64;
pub const PERF_EVENT_IOC_DISABLE: u64 = 9217u64;
pub const PERF_EVENT_IOC_RESET: u64 = 9219u64;

pub fn perf_count_sw_context_switches() -> Box<perf_event_attr> {
    let mut pe: perf_event_attr = Default::default();
    pe.event_type = 1; // SOFTWARE
    pe.event_size = std::mem::size_of::<perf_event_attr>() as u32;
    pe.config = 3; // PERF_COUNT_SW_CONTEXT_SWITCHES
    pe.event_control.set_disabled(true);
    pe.sample.sample_period = 1;
    Box::new(pe)
}
