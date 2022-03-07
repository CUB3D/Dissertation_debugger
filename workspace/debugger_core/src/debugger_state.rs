#[cfg(target_os = "windows")]
use crate::{Breakpoint, Process, FpRegs};
#[cfg(target_os = "macos")]
use crate::{Breakpoint, Process, FpRegs};
use crossbeam_channel::{Receiver, Sender};

#[cfg(target_os = "linux")]
use ptrace::{Breakpoint, Process, FpRegs};
use std::io::Cursor;
use std::ops::Range;
use std::time::Duration;

use crate::common_binary_file::BinaryFile;
use crate::{DebuggerMsg, DebuggingClient, Msg, NativeDebuggingClient};

use crate::MemoryMap;
use crate::UserRegs;
use crate::CallStack;
use crate::Syscall;

//TODO: ideas
// have some way of saying that we don't care about some state so that the client wont bother sending it e.g memory maps
// dont send data that hasn't changed?

/// The current state of a process or thread
/// While windows conceptually has a difference between threads and processes, linux does not so for simplicity we merge these concepts together
pub struct ProcessState {
    /// A reference to the process being debugged,
    /// this *may* actually be a reference to either a process of a thread on windows
    /// on linux this always references a process
    pub process: Process,
    /// The last known state of the process registers, boxed as this can be too large to store on the stack in some cases
    pub cache_user_regs: Option<Box<UserRegs>>,
    /// The last known state of the floating point registers, boxed as this can be too large to store on the stack in some cases
    pub cache_fp_regs: Option<Box<FpRegs>>,
    /// The entire memory space of the process, this will likely be *huge*
    pub memory: Vec<(Vec<u8>, Range<usize>)>,
    /// The current call stack of the process, if available
    pub call_stack: Option<CallStack>,
    /// The current memory map of the process, if available
    pub memory_map: Option<MemoryMap>,
    /// The syscall history of the process
    pub syscall_list: Vec<Syscall>,
}

impl ProcessState {
    /// Create a new `ProcessState` for the given process id, all other fields are set to default values
    pub fn with_process(pid: Process) -> Self {
        Self {
            process: pid,
            cache_user_regs: None,
            cache_fp_regs: None,
            memory: Vec::new(),
            call_stack: None,
            memory_map: None,
            syscall_list: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct DebuggerState {
    pub breakpoints: Vec<Breakpoint>,
    pub process: Option<Process>,
    pub process_state: Vec<ProcessState>,
    pub elf: Option<BinaryFile>,
    pub auto_stp: bool,
    pub single_step_mode: bool,
    pub started: bool,
    pub current_breakpoint: Option<Breakpoint>,
    pub halt_reason: String,
    //TODO: group these three together, if we have one we should have all
    pub sender: Option<Sender<Msg>>,
    pub reciever: Option<Receiver<DebuggerMsg>>,
    pub client: Option<NativeDebuggingClient>,
}

impl DebuggerState {
    pub fn load_binary(&mut self, binary: &str) {
        let binary_content = std::fs::read(&binary).expect("Failed to read binary");

        // if let Ok(fr) = fat_macho::FatReader::new(&binary_content) {
        //     self.elf = Some(BinaryFile::MachO);
        // } else {
            if let Ok(elf) = crate::elf::parse(&mut Cursor::new(binary_content.clone())) {
                let gelf = goblin::elf::Elf::parse(&binary_content).unwrap();
                if let Some(malloc) = gelf.syms.iter().find(|a| gelf.strtab.get_at(a.st_name).unwrap() == "malloc").map(|m| m.st_value as usize) {
                    println!("malloc = {}", malloc);
                }
                //TODO: symbols ui + breakpoints on symbol adding
                // When break on malloc/free track the ptrs

                self.elf = Some(BinaryFile::Elf(elf));
            } //else {
            //     if let Ok(pe) = exe::PEImage::from_disk_file(binary) {
            //         self.elf = Some(BinaryFile::PE(pe));
            //     }
            // }
        // }

        self.client = Some(NativeDebuggingClient::default());
        let (sender, reciever) = self.client.as_mut().unwrap().start(&binary, &[]);
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
                    self.halt_reason = "Trap".to_string();

                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::SyscallTrap => {
                    self.halt_reason = "Syscall Trap".to_string();


                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::BPTrap { breakpoint } => {
                    self.halt_reason = format!("Breakpoint hit @ {:X}", breakpoint.address);

                    // int3 never auto continues
                    self.current_breakpoint = Some(breakpoint);
                }
                DebuggerMsg::ProcessSpawn(p) => {
                    self.process = Some(p);
                    self.process_state.push(ProcessState::with_process(p));
                    self.halt_reason = "Process Started".to_string();
                }
                DebuggerMsg::ChildProcessSpawn(p) => {
                    self.process_state.push(ProcessState::with_process(p));
                    // TODO: hack here, we send this 2 times, onece for the new child, once for the parent
                    self.sender.as_ref().unwrap().send(Msg::Continue);
                    self.sender.as_ref().unwrap().send(Msg::Continue);
                }
                DebuggerMsg::CallStack(pid, cs) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to set call stack for")
                        .call_stack = Some(cs);
                }
                DebuggerMsg::Syscall(pid, s) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to set mmap for")
                        .syscall_list.push(s);
                }
                DebuggerMsg::MemoryMap(pid, mmap) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to set mmap for")
                        .memory_map = Some(mmap);
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
                DebuggerMsg::Memory(pid, mem) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to set mem for")
                        .memory = mem;
                }
                DebuggerMsg::ProcessDeath(pid, status) => {
                    unimplemented!("Proc death");
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
            Msg::Restart => {}
            Msg::Stop => {}
        }
    }

    /// Send a message to the debugging client, while ensuring that any transforms are applied to the local state
    pub fn send_msg(&mut self, msg: Msg) {
        self.apply_state_transform(msg.clone());
        self.sender.as_ref().unwrap().send(msg);
    }
}
