use std::io::Cursor;
use std::time::Duration;
use crossbeam_channel::{Receiver, Sender};
#[cfg(target_os = "linux")]
use ptrace::{Breakpoint, Process};
#[cfg(target_os = "windows")]
use crate::debugging_client::{Breakpoint, Process};

use crate::elf::Elf;
use crate::{DebuggerMsg, DebuggingClient, Msg};
use crate::common_binary_file::BinaryFile;
use crate::debugging_client::NativeDebuggingClient;
use crate::memory_map::MemoryMap;
use crate::registers::UserRegs;
use crate::stack::CallStack;

#[derive(Default)]
pub struct DebuggerState {
    pub syscall_list: Vec<String>,
    pub breakpoints: Vec<Breakpoint>,
    pub process: Option<Process>,
    /// The last known state of the process registers, boxed as this can be too large to store on the stack in some cases
    pub cache_user_regs: Option<Box<UserRegs>>,
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

        if let Ok(elf) = crate::elf::parse(&mut Cursor::new(binary_content)) {
            self.elf = Some(BinaryFile::Elf(elf));
        } else {
            if let Ok(pe) = exe::PEImage::from_disk_file(binary) {
                self.elf = Some(BinaryFile::PE(pe));
            }
        }

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
                DebuggerMsg::Trap {
                    user_regs,
                    fp_regs: _,
                } => {
                    self.cache_user_regs = Some(user_regs);
                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::SyscallTrap {
                    user_regs,
                    fp_regs: _,
                } => {
                    self.cache_user_regs = Some(user_regs);
                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::BPTrap {
                    user_regs,
                    fp_regs: _,
                    breakpoint,
                } => {
                    // int3 never auto continues
                    self.cache_user_regs = Some(user_regs);
                    self.current_breakpoint = Some(breakpoint);
                }
                DebuggerMsg::ProcessSpwn(p) => {
                    self.process = Some(p);
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
