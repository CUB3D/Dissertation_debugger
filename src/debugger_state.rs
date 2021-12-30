#[cfg(target_os = "windows")]
use crate::debugging_client::{Breakpoint, Process, FpRegs};
use crossbeam_channel::{Receiver, Sender};

#[cfg(target_os = "linux")]
use ptrace::{Breakpoint, Process};
use std::io::Cursor;
use std::time::Duration;

use crate::common_binary_file::BinaryFile;
use crate::debugging_client::NativeDebuggingClient;

use crate::memory_map::MemoryMap;
use crate::registers::UserRegs;
use crate::stack::CallStack;
use crate::syscall::Syscall;
use crate::{DebuggerMsg, DebuggingClient, Msg};

pub struct ProcessState {
    pub process: Process,
    /// The last known state of the process registers, boxed as this can be too large to store on the stack in some cases
    pub cache_user_regs: Option<Box<UserRegs>>,
    /// The last known state of the floating point registers, boxed as this can be too large to store on the stack in some cases
    pub cache_fp_regs: Option<Box<FpRegs>>,
}

#[derive(Default)]
pub struct DebuggerState {
    pub syscall_list: Vec<Syscall>,
    pub breakpoints: Vec<Breakpoint>,
    pub process: Option<Process>,
    pub process_state: Vec<ProcessState>,
    pub elf: Option<BinaryFile>,
    pub auto_stp: bool,
    pub single_step_mode: bool,
    pub started: bool,
    pub current_breakpoint: Option<Breakpoint>,
    pub call_stack: Option<CallStack>,
    pub memory_map: Option<MemoryMap>,
    //TODO: group these three together, if we have one we should have all
    pub sender: Option<Sender<Msg>>,
    pub reciever: Option<Receiver<DebuggerMsg>>,
    pub client: Option<NativeDebuggingClient>,
}

impl DebuggerState {
    pub fn load_binary(&mut self, binary: &str) {
        let binary_content = std::fs::read(&binary).expect("Failed to read binary");

        // if let Ok(elf) = crate::elf::parse(&mut Cursor::new(binary_content)) {
        //     self.elf = Some(BinaryFile::Elf(elf));
        // } else {
            if let Ok(pe) = exe::PEImage::from_disk_file(binary) {
                self.elf = Some(BinaryFile::PE(pe));
            }
        // }

        self.client = Some(NativeDebuggingClient::default());
        let (sender, reciever) = self.client.as_mut().unwrap().start(&binary);
        self.sender = Some(sender);
        self.reciever = Some(reciever);
    }

    pub fn process_incoming_message(&mut self) {
        if let Ok(msg) = self
            .reciever
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_nanos(1))
        {
            match msg {
                DebuggerMsg::Trap => {
                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::SyscallTrap => {
                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::BPTrap { breakpoint } => {
                    // int3 never auto continues
                    self.current_breakpoint = Some(breakpoint);
                }
                DebuggerMsg::ProcessSpawn(p) => {
                    self.process = Some(p);
                    self.process_state.push(ProcessState {
                        process: p,
                        cache_user_regs: None,
                        cache_fp_regs: None,
                    });
                }
                DebuggerMsg::ChildProcessSpawn(p) => {
                    self.process_state.push(ProcessState {
                        process: p,
                        cache_user_regs: None,
                        cache_fp_regs: None,
                    });
                    self.sender.as_ref().unwrap().send(Msg::Continue);
                }
                DebuggerMsg::CallStack(cs) => {
                    self.call_stack = Some(cs);
                }
                DebuggerMsg::Syscall(s) => {
                    self.syscall_list.push(s);
                }
                DebuggerMsg::MemoryMap(mmap) => {
                    self.memory_map = Some(mmap);
                }
                //TODO: maybe merge these?
                DebuggerMsg::UserRegisters(pid, user_regs) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to set regs for")
                        .cache_user_regs = Some(user_regs);
                }
                DebuggerMsg::FpRegisters(pid, fp_regs) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to set regs for")
                        .cache_fp_regs = Some(fp_regs);
                }
            }
        }
    }

    /// Apply a message to the current state to transform it into the new state
    /// As long as this is always called on the local state for all sent messages and on the remote state
    /// for all recieved messages -> the two states will always remain in sync
    pub fn apply_state_transform(&mut self, msg: Msg) {
        match msg {
            Msg::Start => {}
            Msg::Continue => {}
            Msg::SingleStep(_) => {}
            Msg::AddBreakpoint(b) => self.breakpoints.push(b),
            Msg::RemoveBreakpoint(baddr) => {
                let index = self
                    .breakpoints
                    .iter_mut()
                    .position(|b| b.address == baddr)
                    .expect("Failed to find bp");
                self.breakpoints.remove(index);
            }
            Msg::InstallBreakpoint { .. } => {}
            Msg::DoSingleStep => {}
        }
    }

    /// Send a message to the debugging client, while ensuring that any transforms are applied to the local state
    pub fn send_msg(&mut self, msg: Msg) {
        self.apply_state_transform(msg.clone());
        self.sender.as_ref().unwrap().send(msg);
    }
}
