use std::marker::PhantomData;
use std::ptr::NonNull;

use libc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use nix::unistd::Pid;
use nix::sys::signal::Signal;

use syscalls::SyscallNo;
use crate::config::*;

/// The interface satisfied by a complete Systrace instrumentation tool.
///
/// The trait is implemented for the global state type, and thus this is what is used 
/// to distinguish one tool from another.
pub trait Tool where
// Self::Tmp: Debug,
// Processor- and Thread-local state may need to migrated:
    Self::Proc: Serialize + DeserializeOwned,
    Self::Thrd: Serialize + DeserializeOwned,
// In contrast, the global state should serialize into a remote 
// HANDLE that allows RPC communication with the original.
// Self::Glob: Serialize,
    Self::GlobMethodArgs : Serialize + DeserializeOwned,
    Self::GlobMethodResult : Serialize + DeserializeOwned,
    Self: std::marker::Sized,
{
    /// Global state shared by the tool across the whole process tree being instrumented.
    type Glob;
    // type Glob = Self;
    // type Glob = Remote<Self>;
    
    /// Arguments to a global state RPC.  This is weakly typed, muxing together 
    /// all different methods of the global state object!
    type GlobMethodArgs;
    /// Corresponding method results. 
    type GlobMethodResult;

    /// Tool state specific to the guest process.
    type Proc;
    /// Tool state specific to the guest thread.
    type Thrd;
    // Temporary state used to represent a tool's computation in the middle of
    // injecting a fresh syscall or funcall in the guest.
    // type Tmp;

    /// Initialize the tool, allocating the global state.
    ///
    /// Takes an optional buffer in which to allocate shared, global state.  
    /// This feature is unimplemeneted, but included for forward portability.
    ///
    fn init_global_state(gbuf: Option<NonNull<u8>>) -> Self::Glob;

    /// Recieve an RPC-upcall on the global state object.
    fn receive_rpc<I: Instrumentor>(g: &mut Self::Glob, args : Self::GlobMethodArgs, i : &mut I)
                                    -> Self::GlobMethodResult;

    // Make a remote procedure call either locally or remotely, as appropriate.
    fn exec_rpc<I: Instrumentor>(g: &mut Remoteable<Self::Glob>, args : Self::GlobMethodArgs, i : &mut I)
                                 -> Self::GlobMethodResult 
    {
        match g {
            Remoteable::Local(gl) => <Self as Tool>::receive_rpc::<I>(gl, args, i),
            Remoteable::Remote(_ref) => {
                let s = serde_json::to_vec(&args).unwrap();
                let r = i.send_rpc_sync(s);
                let r2 : Self::GlobMethodResult = serde_json::from_slice::<>(& r).unwrap();
                r2
            }
        }
    }

    /// Trigger to initialize state when a process is created, including the root process.
    /// Every process includes at least one thread, so this returns a thread state as well.
    /// 
    /// For now this assumes access to the global state, but that may change.
    fn init_process_state(g: &Remoteable<Self::Glob>, id : Pid ) -> (Self::Proc, Self::Thrd);

    /// A guest process creates additional threads, which need their state initialized.
    /// This takes the thread-local state of the PARENT thread for reference.
    fn init_thread_state(g: &Remoteable<Self::Glob>, p: &Self::Proc, parent: &Self::Thrd, id : Pid) -> Self::Thrd;

    /// The tool receives an event from the instrumentation.
    ///
    /// This is where all the action happens.  This async method can make asynchronous calls
    /// against either (1) the global state (remote object), or (2) the injector.
    /// In either case, it is registering a continuation to respond to the completion of an RPC
    /// in the host (coordinator) or guest respectively.
    fn handle_event<I: Instrumentor>(g: &mut Remoteable<Self::Glob>, p: &mut Self::Proc, t: 
                                     &mut Self::Thrd, i : &mut I, e : Event);
    //  TODO: in the future each event handled may return a result to the instrumentor 
    // which changes its configuration: for example, subscribing or unsubscribing to 
    // categories of events.

    // Optionally override this as an optimization.  By default it will send the event 
    // to the respective
    // fn handle_global_event<I: Injector>(e : Event, i: I, g: Self::Glob) -> ();
}

/// A reference to an object that MAY reside on another machine.
pub enum Remoteable<T> {
    Local(T),
    Remote(RemoteRef<T>)
}

/// A reference to an object on a remote machine
/// 
/// TODO: replace this with the appropriate concept from a popular RPC library.
pub struct RemoteRef<T> {    
    id : u64,
    phantom : PhantomData<T>,
}

/// Run code *inside* a guest process.
///
/// The Injector interface provides the "downcalls".
/// The injector inserts either new system calls or function calls into the guest.  
/// It does *not* create (JIT compile) new functions in the guest, rather it calls
/// existing functions. (Though it does inject new code in the case of individual syscalls.)
///
/// NOTE: there is currently no way to inject *signals* into the guest.  Rather, one must
/// inject the functional calls, and instead intercept and prevent attempts by the guest
/// to register signal handlers in the first place.
pub trait Injector {
    /// Inject a system call into the guest and register the callback.
    /// Note that the callback will be called twice in the case of a Fork.
    fn inject_syscall(&self, _: SyscallNo, _: SysArgs, k: fn(_: SysCallRet) -> ());

    /// Look up the address of a function within the guest.
    fn resolve_symbol_address(&self, _: Pid, _: String) -> FunAddr;

    /// Run a function in the guest.
    ///
    /// TODO: ideally a tool implementing SystraceTool would be able to
    /// call its own functions within the guest without indirecting through the
    fn inject_funcall(&self, func: FunAddr, args: &[u64; 6]) -> i64;

    /// Wait for the guest to exit.
    fn wait_exit();

    // inject_signal(...) -> ...;
}

/// Full access to the Guest includes the ability to inject,
///  as well as the ability to access the guest's state.
pub trait GuestAccess : Injector {
    fn get_regs(&self) -> Regs;
    fn get_static_config(&self) -> StaticConfig;
    fn get_dynamic_config(&self) -> DynConfig;
}

type Regs = libc::user_regs_struct;
type SerializedVal = Vec<u8>;
type FunAddr = u64;
type SysCallRet = i64;

/// The 6 arguments of a syscall, raw untyped version.
///
/// TODO: Use a helper function to convert to a structured Syscall+Args enum.
#[derive(PartialEq, Debug, Eq, Clone)]
pub struct SysArgs {
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

#[derive(PartialEq, Debug, Eq, Clone)]
pub enum Instr {
    RDTSC,    
    CPUID,
    // Future, no current way to trap:
    // RDRAND,
    // HTX instructions...
}

// TODO: Full "Instrumentor" interface that allows sending global RPCs as well.
pub trait Instrumentor : GuestAccess { 
    /// Send an RPC message to wherever the global state is stored, 
    /// synchronously block until a response is received.
    fn send_rpc_sync(self : &mut Self, args : SerializedVal) -> SerializedVal;

    // TODO - async version that returns a future.
    // fn send_rpc_async<F>(self : Self, args : SerializedVal) -> F
    //      where F: Future<Item=SerializedVal>;
    // fn send_rpc_async<F>(self : Self, args : String) -> impl Future<Item=String, Error=String>;
}

/// Events are the guest actions/state changes that the tool responds to.
///
/// These are the "upcalls" into the tool, from the guest(s).
///
#[derive(PartialEq, Debug, Eq, Clone)]
pub enum Event {
    /// An attempt to execute a syscall inside the guest.  Note, the interceptor
    /// may configured to only intercept a *subset* of syscalls, which will prune the events
    /// that appear in this form.
    Syscall(SyscallNo, SysArgs),

    /// A trapped instruction in the guest, other than a syscall.
    Instruction(Instr),

    /// A signal received within the guest.
    Signal(Signal),

    /// An (optional) notification that exit will happen for this thread.
    /// QUESTION: Can this be removed?
    PreExit(Pid),

    /// Exit of a thread.  This is not defined as requiring that the OS has freed 
    /// resources.  Rather, the definition is that no further events or observable 
    /// side effects will be seen from this TID.
    ExitThread(Pid),
    /// Same but for processes.
    ExitProc(Pid),

    /// Future/TODO: 
    /// Timer/heartbeat events: for future use with a deterministic (DLC) implementation.
    /// The guest yields cooperatively when it finishes its logical time slice.
    /// The heartbeat carries with it the current thread time, in whatever unit was requested.
    HeartbeatYield(u64),
}

/// An Event together with information on where it came from.
pub struct FullEvent {
    e : Event,
    tid : Pid,
    pid : Pid,
    // Other context....?
}
