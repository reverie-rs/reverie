use std::ptr::NonNull;
use std::fmt::Debug;
use serde::{Serialize};
use nix::sys::signal::Signal;
use libc::pid_t;

/// This is parametric over GlobalState, ProcessState, ThreadState (G,P,T).
// pub trait SystraceTool<G,P,T> 
// fn init_state( gbuf : Option< NonNull<u8> > ) -> (Option<G>, Option<P>, Option<T>);

//--------------------------------------------------------------

/// Events are the guest actions/state changes that the tool responds to.
/// 
/// These are te "upcalls".
/// 
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub enum Event {
    /// An attempt to execute a syscall inside the guest.  Note: the interceptor 
    /// may configured to only intercept a subset of syscalls.
    Syscall(SysNo, SysArgs),
    /// An (optional) notification that exit will happen for this thread.
    PreExit(TID),
    /// True exit of a thread.
    ActualExit(TID),
    /// A signal received within the guest.
    Signal(Signal),
}

/// Run code *inside* a guest process.
/// 
/// These are the "downcalls".
/// The injector inserts either new system calls or function calls into the guest.  
/// It does not create new functions in the guest, rather it calls existing functions.
/// (Though it does inject new code in the sense of individual syscalls.)
/// 
/// NOTE: there is currently no way to inject signals into the guest.  Rather, one must
/// inject the functional calls directly, and intercept attempts to register signal handlers 
/// in the first place.
pub trait Injector {
    /// Inject a system call into the guest and register the callback 
    fn inject_syscall(_:SysNo, _:SysArgs, k: fn (_:SysCallRet) -> ()) -> ();

    fn resolve_symboll() -> ();
    fn inject_funcall() -> ();

    /// We distinguish injecting forks from other syscalls, because the 
    /// continuation is invoked twice for this action.
    fn inject_fork( p : pid_t ) -> ();

    fn wait_exit() -> (); 

    // inject_signal(...) -> ...; 
}

/// 
pub type Regs = u8;

pub trait RegsAccess {

}

pub trait GuestAccess : Injector {
  fn get_regs() -> Regs;
}

/// The interface satisfied by a complete Systrace instrumentation tool.
/// 
/// 
/// 
pub trait SystraceTool
where
    Self::Glob : Debug,
    Self::Proc : Debug,
    Self::Thrd : Debug, 
    Self::Tmp : Debug,
    Self::Proc : Serialize,  
    Self::Thrd : Serialize,
{
    /// Global state shared by the tool across the whole process tree being instrumented.
    type Glob;    
    /// Tool state specific to the guest process.
    type Proc;
    /// Tool state specific to the guest thread.
    type Thrd;
    /// Temporary state used to represent a tool's computation in the middle of 
    /// injecting a fresh syscall or funcall in the guest.
    type Tmp;

    /// Initialize the tool, allocating the corresponding pieces of state.
    /// 
    /// Takes an optional (FUTURE).  This feature is unimplemeneted, 
    /// but included for forward portability.
    /// 
    fn init_state( gbuf : Option< NonNull<u8> > ) 
        -> (Option<Self::Glob>, Option<Self::Proc>, Option<Self::Thrd>);

    fn handle_event<I : Injector>(i : I) -> ();

    // Optionally override this as an optimization.
    fn handle_global_event( goo : u8 ) -> ();

}

//--------------------------------------------------------------
// TODO / unfinished
//--------------------------------------------------------------

/// TODO: thread ID
pub type TID = u64;

// The value returned in RAX on x86_64:
pub type SysCallRet = i64;

/// The 6 arguments of a syscall, raw untyped version.
/// 
/// TODO: Use a helper function to convert to a structured Syscall+Args enum.
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub struct SysArgs {
    arg0 : u64,
    arg1 : u64,
    arg2 : u64,
    arg3 : u64,
    arg4 : u64,
    arg5 : u64
}

// TODO Grab this enum from the lib:
pub type SysNo = u8;
pub type SigNo = u8;

//--------------------------------------------------------------
fn main() {
    println!("Hello, world!");
    
}
