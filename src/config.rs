
use syscalls::*;

/// How should the intrumentor do its job?
pub enum InstrumentMode {
    /// Fully centralized tool execution inside a tracer process.  
    /// 
    /// This uses ptrace to handle all events, and for all guest access/modification.
    FullPtrace,

    /// Execute event handlers inside guest process when possible.  
    /// 
    /// In this default setting, local handlers communicate with the 
    /// global state object using ________, the default RPC 
    /// implementation.  Global state methods run centrally in a tracer
    /// and they read and modify (inject) the guest processes using ptrace.
    InGuestDefault,

    // TODO: in the future we may offer a mode for executing global methods 
    // in a decentralized fashion, assuming threadsafe implementations and all 
    // global state managed in shared pages.  We're setting aside this option 
    // for the near and medium term.
    //
    // GlobalSharedState
}

/// Setting to optionally interupt the guest (fire a timer) causing an event to be 
/// created and handled by the tool.
pub enum Heartbeat {
    /// No heartbeat.  Guests will only yield when they trigger a relevant event, 
    /// not merely due to the passage of time.
    NoBeat,

    /// Future/TODO: A maximum guest compute quantum, specified in units of 
    /// retired branch conditionals.  This heartbeat can be used to construct 
    /// a deterministic logical clock (DLC), but it is expensive, because current
    /// (2019) Intel hardware does not support exact interrupts on this perf counter
    /// so some single-stepping is required (see RR ATC'17 paper).
    /// 
    /// The boolean indicates whether other handled events "count" as heartbeats.
    /// If true, then the heartbeat only triggers if and when the guest exceeds
    /// its time slice before yielding with a syscall or some other event.
    ExactRBCs(u64, bool),

    /// Future/TODO: a nondeterministic heartbeat that is less expensive to implement.
    /// This can be useful for updating ones own clock, for example (i.e. in a scenario 
    /// where we do not yield on heartbeats, but do publish state).
    ApproxCyclesRBCs(u64, bool),

    /// Future/TODO: The same as above, but in units of cycles rather than RBCs.
    ApproxCycles(u64, bool),
}

/// Dynamic configuration options that may change after each handler execution.
pub struct DynConfig {
    /// Interrupt the guest, bounding how long the guest can run without an event.
    pub heartbeat : Heartbeat,
}

impl DynConfig {
    pub fn new() -> Self {
        DynConfig {
            heartbeat: Heartbeat::NoBeat,
        }
    }
}

impl Default for DynConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Instrumentor configuration set at startup time.
pub struct StaticConfig {
    pub mode : InstrumentMode,
    pub init_dynconfig : DynConfig,
    /// Specifies which syscalls should be intercepted by the tool.
    /// Only syscalls that return `true` here will result in `handle_event` calls.
    pub syscall_filter : fn (SyscallNo) -> bool
}

fn syscall_filter_none(_nr: SyscallNo) -> bool {
    false
}

impl StaticConfig {
    pub fn new() -> Self {
        StaticConfig {
            mode: InstrumentMode::InGuestDefault,
            init_dynconfig: DynConfig::new(),
            syscall_filter: syscall_filter_none,
        }
    }

    pub fn mode(&mut self, mode: InstrumentMode) -> &mut Self {
        self.mode = mode;
        self
    }

    pub fn filter(&mut self, pfn: fn (SyscallNo) -> bool) -> &mut Self {
        self.syscall_filter = pfn;
        self
    }
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self::new()
    }
}
