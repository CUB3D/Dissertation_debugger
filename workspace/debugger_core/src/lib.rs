//! A client for debugging a given process, handles process spawning and event handling for a given platform
#![feature(seek_stream_len)]
pub mod types;
pub mod debugger_state;
pub mod common_binary_file;
pub mod elf;
pub use types::*;
pub use debugger_state::*;
pub use elf::*;
use std::ops::Range;
use crossbeam_channel::{Receiver, Sender};

pub trait DebuggingClient {
    //TODO: should this return an instance of the client
    fn start(&mut self, binary_path: &str, args: &[&str]) -> (Sender<Msg>, Receiver<DebuggerMsg>);
}
#[cfg(target_os = "linux")]
pub use ptrace::{Breakpoint, FpRegs, Process};

use crate::types::MemoryMap;
use crate::types::UserRegs;
use crate::types::CallStack;
use crate::types::Syscall;

#[cfg(target_os = "linux")]
pub mod linux_ptrace_debugging_client;
#[cfg(target_os = "windows")]
pub mod windows_debugging_client;
#[cfg(target_os = "macos")]
pub mod mac_debugging_client;

#[cfg(target_os = "linux")]
pub use linux_ptrace_debugging_client::LinuxPtraceDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "windows")]
pub use windows_debugging_client::WindowsNTDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "macos")]
pub use mac::DarwinDebuggingClient as NativeDebuggingClient;

#[cfg(not(target_os = "linux"))]
#[derive(Copy, Clone, Debug)]
pub struct Breakpoint {
    pub address: usize,
}
#[cfg(not(target_os = "linux"))]
impl Breakpoint {
    pub fn new(address: usize) -> Self {
        Self { address }
    }
}
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
pub struct FpRegs {
    pub ftw: libc::c_ushort,
    pub st_space: [libc::c_uint; 32],
    pub xmm_space: [libc::c_uint; 64],
}
#[cfg(not(target_os = "linux"))]
#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Process(pub i32);

/// Messages send from the ui to the debugging client
#[derive(Clone)]
pub enum Msg {
    /// Start running an instance of the binary
    Start,
    /// Resume executing the binary
    Continue,
    /// Set wether to single step (true) or syscall step (false)
    SingleStep(bool),
    /// Register and install a breakpoint
    AddBreakpoint(Breakpoint),
    /// Remove the breakpoint at the given address
    RemoveBreakpoint(usize),
    /// Install the breakpoint that has already been added at the given address
    InstallBreakpoint {
        address: usize,
    },
    DoSingleStep,
    /// Restart the running process
    Restart,
    /// Stop the process
    Stop
}

/// Messages send from the debugging client to the ui to notify of an event
#[derive(Clone, Debug)]
pub enum DebuggerMsg {
    /// The child has hit a singlestep breakpoint, control returned to caller
    Trap,
    /// The child has hit a int3 breakpoint, control returned to caller at the start of the
    /// original instruction that was overwriten with the bp
    /// At this point the breakpoint is no longer active, it can be reinstalled with
    /// InstallBreakpoint, however this must be done after executing past this point
    /// or it will be hit in a loop.
    BPTrap { breakpoint: Breakpoint },
    /// The child has hit a syscall breakpoint, control returned to caller
    SyscallTrap,
    /// The process has spawned
    ProcessSpawn(Process),
    /// The given process has died with the given status
    ProcessDeath(Process, isize),
    /// A child process has spawned
    ChildProcessSpawn(Process),
    /// The process has stopped, we have a new call stack to display
    CallStack(Process, CallStack),
    /// The process has executed a syscall
    Syscall(Process, Syscall),
    /// The process is updating the memory map
    MemoryMap(Process, MemoryMap),
    /// The given process has received new user registers
    UserRegisters(Process, Box<UserRegs>),
    /// The given process has received new floating point registers
    FpRegisters(Process, Box<FpRegs>),
    /// The given process has new memory state
    Memory(Process, Vec<(Vec<u8>, Range<usize>)>),
}
