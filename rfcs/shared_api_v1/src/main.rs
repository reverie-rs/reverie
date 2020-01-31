/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#![feature(async_await)]
#![allow(dead_code)]

use nix::unistd;
use nix::unistd::Pid;
use nix::sys::signal::Signal;
use std::ptr::NonNull;
use std::marker::PhantomData;

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use serde_json;

/// Instrumentor configuration set at startup time.
pub struct StaticConfig {
    mode : InstrumentMode,
    init_dynconfig : DynConfig,
}

/// Dynamic configuration options that may change after each handler execution.
pub struct DynConfig {
    /// Interrupt the guest, bounding how long the guest can run without an event.
    heartbeat : Heartbeat,
    /// Specifies which syscalls should be intercepted by the tool.
    /// Only syscalls that return `true` here will result in `handle_event` calls.
    syscall_filter : fn (SysNo) -> bool
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

/// Events are the guest actions/state changes that the tool responds to.
///
/// These are the "upcalls" into the tool, from the guest(s).
///
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub enum Event<PState,TState> {
    /// An attempt to execute a syscall inside the guest.  Note, the interceptor
    /// may configured to only intercept a *subset* of syscalls, which will prune the events
    /// that appear in this form.
    Syscall(SysNo, SysArgs),

    /// A trapped instruction in the guest, other than a syscall.
    Instruction(Instr),

    /// A signal received within the guest.
    Signal(Signal),

    /// An (optional) notification that exit will happen for this thread.
    /// QUESTION: Can this be removed?
    PreExit(TID),

    /// Exit of a thread.  This is not defined as requiring that the OS has freed
    /// resources.  Rather, the definition is that no further events or observable
    /// side effects will be seen from this TID.
    ///
    /// When we process an exit-thread event, we get a copy of the
    /// final thread-local state.  Typically, this is so we can send
    /// appropriate updates to the global state before the thread
    /// local state is lost.
    ExitThread(TID, TState),

    /// The same as ExitThread but for processes.
    ExitProc(Pid,PState),

    /// Future/TODO:
    /// Timer/heartbeat events: for future use with a deterministic (DLC) implementation.
    /// The guest yields cooperatively when it finishes its logical time slice.
    /// The heartbeat carries with it the current thread time, in whatever unit was requested.
    HeartbeatYield(u64),
}

/// An Event together with information on where it came from.
pub struct FullEvent<Ps,Ts> {
    e : Event<Ps,Ts>,
    tid : TID,
    pid : Pid,
    // Other context....?
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
    fn inject_syscall(&self, _: SysNo, _: SysArgs, k: fn(_: SysCallRet) -> ()) -> ();

    /// Look up the address of a function within the guest.
    fn resolve_symbol_address(&self, _: Pid, _: String) -> FunAddr;

    /// Run a function in the guest.
    ///
    /// TODO: ideally a tool implementing SystraceTool would be able to
    /// call its own functions within the guest without indirecting through the
    fn inject_funcall(&self, func: FunAddr, args: &[u64; 6]) -> i64;

    /// Wait for the guest to exit.
    fn wait_exit() -> ();

    // inject_signal(...) -> ...;
}

/// This can either be all registers together in memory, or an interface
/// for fetching them one at a time.
pub struct Regs {
    rax: u64,
    // ...
}

pub trait RegsAccess {
    // TODO
}


/// Full access to the Guest includes the ability to inject,
///  as well as the ability to access the guest's state.
pub trait GuestAccess : Injector {
    fn get_regs(&self) -> Regs;
    fn get_static_config(&self) -> StaticConfig;
    fn get_dynamic_config(&self) -> DynConfig;
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
// FIXME: need some kind of UID/remote-handle here.
// TODO: this probably needs some local, mutable state regarding the reference,
// for example, to track outstanding RPC calls.


/// The interface satisfied by a complete Systrace instrumentation tool.
///
/// The trait is implemented for the global state type, and thus this is what is used
/// to distinguish one tool from another.
pub trait SystraceTool
where
    // Self::Tmp: Debug,
    // Processor- and Thread-local state may need to migrated:
    Self::Proc: Serialize,
    Self::Proc: DeserializeOwned,
    Self::Thrd: Serialize,
    Self::Thrd: DeserializeOwned,
    // In contrast, the global state should serialize into a remote
    // HANDLE that allows RPC communication with the original.
    // Self::Glob: Serialize,
    Self::GlobMethodArgs : Serialize,
    Self::GlobMethodArgs : DeserializeOwned,
    Self::GlobMethodResult : Serialize,
    Self::GlobMethodResult : DeserializeOwned,
    Self : std::marker::Sized,
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
            Remoteable::Local(gl) => <Self as SystraceTool>::receive_rpc::<I>(gl, args, i),
            Remoteable::Remote(_ref) => {
               let s = serde_json::to_string(&args).unwrap();
               let r = i.send_rpc_sync(s);
               let r2 : Self::GlobMethodResult = serde_json::from_str::<>(& r).unwrap();
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
    fn init_thread_state(g: &Remoteable<Self::Glob>, p: &Self::Proc, parent: &Self::Thrd, id : TID)
       -> Self::Thrd;

    /// The tool receives an event from the instrumentation.
    ///
    /// This is where all the action happens.  This async method can make asynchronous calls
    /// against either (1) the global state (remote object), or (2) the injector.
    /// In either case, it is registering a continuation to respond to the completion of an RPC
    /// in the host (coordinator) or guest respectively.
    fn handle_event<I: Instrumentor>(g: &mut Remoteable<Self::Glob>, p: &mut Self::Proc, t:
                                     &mut Self::Thrd,
                                     i : &mut I,
                                     e : Event<Self::Proc, Self::Thrd>) -> ();
        //  TODO: in the future each event handled may return a result to the instrumentor
        // which changes its configuration: for example, subscribing or unsubscribing to
        // categories of events.

    // Optionally override this as an optimization.  By default it will send the event
    // to the respective
    // fn handle_global_event<I: Injector>(e : Event, i: I, g: Self::Glob) -> ();
}

//--------------------------------------------------------------
// TODO / unfinished
//--------------------------------------------------------------

/// Thread ID
pub type TID = Pid;

// TODO: replace this with whatever is most idiomatic.
pub type SerializedVal = String;

// The value returned in RAX on x86_64:
pub type SysCallRet = i64;

/// The 6 arguments of a syscall, raw untyped version.
///
/// TODO: Use a helper function to convert to a structured Syscall+Args enum.
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub struct SysArgs {
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub enum Instr {
    RDTSC,
    CPUID,
    // Future, no current way to trap:
    // RDRAND,
    // HTX instructions...
}

// TODO Grab this enum from the lib:
pub type SysNo = u64;
pub type SigNo = u64;
pub type FunAddr = u64;

//--------------------------------------------------------------
// Example tool: a simple counter.

/// A counter tool, keeping the simplest possible global state: a number.
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub struct CounterTool {}
// AUDIT: is this singleton type idiomatic?

/// Type-safe wrapper-methods for RPC calls.  These could be generated.
impl CounterTool {
    fn incr<I : Instrumentor>(g: &mut Remoteable<u64>, i : &mut I, x : u64) -> () {
       Self::exec_rpc(g, IncrMsg(x), i);
    }
}

#[derive(PartialEq, Debug, Eq, Hash, Clone, Deserialize)]
pub struct IncrMsg(u64);

// [derive(Serialize,Deserialize)]
// [serde(tag = "type")]

impl Serialize for IncrMsg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S : serde::Serializer,
    {
        match self {
            IncrMsg(n) => n.serialize(serializer)
        }
    }
}

impl SystraceTool for CounterTool {
    type Glob = u64;
    type GlobMethodArgs = IncrMsg;
    type GlobMethodResult = ();

    type Proc = ();
    type Thrd = ();

    fn init_global_state(gbuf: Option<NonNull<u8>>) -> u64 {
        assert!(gbuf.is_none());
        0 // Counter{count:0}
    }

    fn init_process_state(_g :& Remoteable<u64>, _ : Pid) -> ((),()) {
        ((),())
    }

    fn init_thread_state(_g : &Remoteable<u64>, _p: &Self::Proc, _parent: &Self::Thrd, _ : TID) {
        ()
    }

    fn handle_event<I:Instrumentor>(g: &mut Remoteable<Self::Glob>,
                                    _p: &mut Self::Proc,
                                    _t: &mut Self::Thrd,
                                    i : &mut I,
                                    e : Event<Self::Proc, Self::Thrd>) {
        println!(" - Counter tool recv event: {:?}", e);
        match e {
            Event::Syscall(_,_) => Self::incr(g, i, 1),
            _ => ()
        }
        ()
    }

    fn receive_rpc<I:Instrumentor>(g: &mut u64, args: Self::GlobMethodArgs, _i : &mut I) {
        match args {
          IncrMsg(n) => *g += n
        }
    }
}

//--------------------------------------------------------------

/// Fake Instrumentor
pub struct FakeInstrumentor {}

impl Injector for FakeInstrumentor {
    fn inject_syscall(&self, s: SysNo, a: SysArgs, _k: fn(_: SysCallRet) -> ()) {
       println!(" [FakeInstrumentor] inject syscall {:?},{:?}", s, a);
    }

    fn resolve_symbol_address(&self, _: Pid, s: String) -> FunAddr {
        println!(" [FakeInstrumentor] resolve symbol {}", s);
        0
    }

    fn inject_funcall(&self, func: FunAddr, _args: &[u64; 6]) -> i64 {
        println!(" [FakeInstrumentor] called fun {}", func);
        0
    }

    fn wait_exit() {

    }
}

const DEFAULT_DYNCONFIG : DynConfig = DynConfig {
    heartbeat: Heartbeat::NoBeat,
    syscall_filter: |_| true
};

impl GuestAccess for FakeInstrumentor {
    fn get_regs(&self) -> Regs {
        println!(" [FakeInstrumentor] reading registers..");
        Regs {
            rax: 3
        }
    }
    fn get_static_config(&self) -> StaticConfig {
        println!(" [FakeInstrumentor] reading static config...");
        StaticConfig {
            init_dynconfig: DEFAULT_DYNCONFIG,
            mode : InstrumentMode::FullPtrace
        }
    }
    fn get_dynamic_config(&self) -> DynConfig {

        DEFAULT_DYNCONFIG
    }
}

impl Instrumentor for FakeInstrumentor {
  fn send_rpc_sync(self : &mut Self, args : SerializedVal) -> SerializedVal {
    println!(" [FakeInstrumentor] Sending RPC with args {}", args);
    // "".to_string() // FIXME
    serde_json::to_string(& ()).unwrap()
  }
}

//--------------------------------------------------------------

/// Hook up the give tool so that it becomes the single, global tool compiled
/// in this library.  This must be called at startup.  It is called in the guest process.
/// Therefore, this will use local, in-process interactions with the guest.
fn register_instrumentation_tool_local<T : SystraceTool>(_t : & T, r : RemoteRef<T::Glob>) {
    let mut rem = Remoteable::Remote(r);
    let (mut ps,mut ts) = T::init_process_state(& rem, unistd::getpid());
    println!(" * Process, and thread state allocated.");

    // Initialize instrumentor:
    let mut inst = FakeInstrumentor{}; // TODO: GUEST mode instrumentor..

    // Temporarily call test events:
    let e = Event::Syscall(0, SysArgs{arg0:0, arg1:1, arg2:2, arg3:3, arg4:4, arg5:5});
    T::handle_event(&mut rem, &mut ps, &mut ts, &mut inst, e);
    T::handle_event(&mut rem, &mut ps, &mut ts, &mut inst, Event::Instruction(Instr::RDTSC));
    ()
}

/// The same as register_instrumentation_tool_local, except called in the global/daemon/tracer
/// process instead.  The tool will therefore interact with the guest remotely, using
/// inter-process communication.
fn register_instrumentation_tool_global<T : SystraceTool>(_t : & T) {
    let _gs = T::init_global_state(None);

    let mut _inst = FakeInstrumentor{}; // TODO: Ptrace-mode instrumentor..

    println!(" * Global state allocated.");
}

/// TODO: replace with some standardized entrypoint for the library, exposed to C code.
fn init_upcall_example() {
    let t = CounterTool{};
    let fakeref = RemoteRef{id:999, phantom: PhantomData};
    register_instrumentation_tool_global(& t);
    register_instrumentation_tool_local(& t, fakeref);
}


//--------------------------------------------------------------
fn main() {
    println!("Initializing tool...");
    init_upcall_example();
    println!("Finish dummy program");
}
