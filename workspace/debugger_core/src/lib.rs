//! A client for debugging a given process, handles process spawning and event handling for a given platform
#![feature(seek_stream_len)]
#![feature(new_uninit)]
pub mod common_binary_file;
pub mod debugger_state;
pub mod types;
// pub mod elf;
pub use debugger_state::*;
pub use types::*;
// pub use elf::*;
use crossbeam_channel::{Receiver, Sender};
use std::ops::Range;

pub trait DebuggingClient {
    //TODO: should this return an instance of the client
    fn start(&mut self, binary_path: &str, args: &[&str]) -> (Sender<Msg>, Receiver<DebuggerMsg>);
}
#[cfg(target_os = "linux")]
pub use ptrace::{Breakpoint, FpRegs, Process};

use crate::types::CallStack;
use crate::types::MemoryMap;
use crate::types::Syscall;
use crate::types::UserRegs;

#[cfg(target_os = "linux")]
pub mod linux_ptrace_debugging_client;
#[cfg(target_os = "macos")]
pub mod mac_debugging_client;
#[cfg(target_os = "windows")]
pub mod windows_debugging_client;

#[cfg(target_os = "linux")]
pub use linux_ptrace_debugging_client::LinuxPtraceDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "macos")]
pub use mac_debugging_client::DarwinDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "windows")]
pub use windows_debugging_client::WindowsNTDebuggingClient as NativeDebuggingClient;

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
#[cfg(target_os = "windows")]
#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Process(pub i32);
#[cfg(target_os = "macos")]
pub use crate::mac_debugging_client::Process;

/// Messages send from the ui to the debugging client
#[derive(Clone, Debug)]
pub enum Msg {
    /// Resume executing the binary
    Continue,
    /// Register and install a breakpoint
    AddBreakpoint(Breakpoint),
    /// Remove the breakpoint at the given address
    RemoveBreakpoint(usize),
    /// Execute for a single step
    DoSingleStep,
    /// Restart the running process
    Restart,
    /// Stop the process
    Stop,
    /// Input for stdin
    StdinData(String),
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
    /// The given process has new data in stderr
    StdErrContent(Process, Vec<u8>),
    /// The given process has new data in stdout
    StdOutContent(Process, Vec<u8>),
}
