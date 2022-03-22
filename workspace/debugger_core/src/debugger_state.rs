#[cfg(target_os = "windows")]
use crate::{Breakpoint, FpRegs, Process};
#[cfg(target_os = "macos")]
use crate::{Breakpoint, FpRegs, Process};
use crossbeam_channel::{Receiver, Sender};

#[cfg(target_os = "linux")]
use ptrace::{Breakpoint, FpRegs, Process};
use std::ops::Range;
use std::time::Duration;

use crate::common_binary_file::BinaryFile;
use crate::{DebuggerMsg, DebuggingClient, Msg, NativeDebuggingClient};

use crate::CallStack;
use crate::MemoryMap;
use crate::Syscall;
use crate::UserRegs;

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
    /// True if the process is currently alive, false if it's dead
    pub alive: bool,
    /// The stderr output for this process
    pub stderr: Vec<String>,
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
            stderr: Default::default(),
            alive: true,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum DebuggerStatus {
    NoBinaryYet,
    ReadyToStart,
    Running,
    Breakpoint,
    Paused,
    Dead,
}

impl Default for DebuggerStatus {
    fn default() -> Self {
        Self::NoBinaryYet
    }
}
impl DebuggerStatus {
    pub fn description(&self) -> String {
        match self {
            Self::NoBinaryYet => format!("Load a binary to start"),
            Self::ReadyToStart => format!("Ready to start"),
            Self::Running => format!("Running"),
            Self::Breakpoint => format!("Breakpoint"),
            Self::Paused => format!("Paused"),
            Self::Dead => format!("Dead"),
        }
    }
}

#[derive(Default)]
pub struct DebuggerState {
    /// All the breakpoints that have been added
    pub breakpoints: Vec<Breakpoint>,
    /// The main or parent of all other processes
    pub process: Option<Process>,
    /// The state of all of the processess
    pub process_state: Vec<ProcessState>,
    /// The loaded file, not always an elf
    pub elf: Option<BinaryFile>,
    /// The breakpoint that has been most recently hit, if it exists
    pub current_breakpoint: Option<Breakpoint>,
    /// The current state of the debugger
    pub status: DebuggerStatus,
    //TODO: group these three together, if we have one we should have all
    pub sender: Option<Sender<Msg>>,
    pub reciever: Option<Receiver<DebuggerMsg>>,
    pub client: Option<NativeDebuggingClient>,
}

impl DebuggerState {
    pub fn load_binary(&mut self, binary: &str) {
        let binary_content = std::fs::read(&binary).expect("Failed to read binary");

        // Try loading file as a ELF
        if let Ok(gelf) = goblin::elf::Elf::parse(&binary_content) {
            if let Some(malloc) = gelf
                .syms
                .iter()
                .find(|a| gelf.strtab.get_at(a.st_name).unwrap() == "malloc@plt")
                .map(|m| m.st_value as usize)
            {
                println!("malloc = {}", malloc);
            } else {
                println!("No malloc");
            }
            //TODO: symbols ui + breakpoints on symbol adding
            // When break on malloc/free track the ptrs

            self.elf = Some(BinaryFile::Elf(binary_content.clone()));
        }

        // Try loading file as a macho (macos)
        if self.elf.is_none() {
            if let Ok(gmacho) = goblin::mach::MachO::parse(&binary_content, 0) {
                self.elf = Some(BinaryFile::MachO);
            } else {
                println!("Failed to load macho");
            }
        }

         //else {
          //     if let Ok(pe) = exe::PEImage::from_disk_file(binary) {
          //         self.elf = Some(BinaryFile::PE(pe));
          //     }
          // }
          // }

        self.client = Some(NativeDebuggingClient::default());
        let (sender, reciever) = self.client.as_mut().unwrap().start(&binary, &[]);
        self.sender = Some(sender);
        self.reciever = Some(reciever);

        self.status = DebuggerStatus::ReadyToStart;
    }

    pub fn process_incoming_message(&mut self) {
        while let Ok(msg) = self
            .reciever
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_nanos(1))
        {
            match msg {
                DebuggerMsg::Trap => {
                    self.status = DebuggerStatus::Paused;
                }
                DebuggerMsg::BPTrap { breakpoint } => {
                    // int3 never auto continues
                    self.current_breakpoint = Some(breakpoint);
                    self.status = DebuggerStatus::Breakpoint;
                }
                DebuggerMsg::ProcessSpawn(p) => {
                    println!("Proc spawn {:?}", p);

                    // This is a restart
                    // TODO: have a reset debugger msg
                    if self.process.is_some() {
                        self.process_state.clear();
                        for bp in &self.breakpoints {
                            self.sender.as_ref().unwrap().send(Msg::AddBreakpoint(*bp)).expect("Failed to send");
                        }
                        self.status = DebuggerStatus::ReadyToStart;
                    }

                    self.process = Some(p);
                    self.process_state.push(ProcessState::with_process(p));
                }
                DebuggerMsg::ChildProcessSpawn(p) => {
                    self.process_state.push(ProcessState::with_process(p));
                }
                DebuggerMsg::CallStack(pid, cs) => {
                    println!("callstack {:?} {:?}", pid, cs);

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
                        .syscall_list
                        .push(s);
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
                DebuggerMsg::ProcessDeath(pid, _status) => {
                    self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to mark dead")
                        .alive = false;

                    //println!("Proc death, pid = {:?}, status = {:?}", pid, status);

                    if !self.process_state.first().unwrap().alive {
                        self.status = DebuggerStatus::Dead;
                    }
                }
                DebuggerMsg::StdErrContent(pid, content) => {
                    let proc = self.process_state
                        .iter_mut()
                        .find(|p| p.process == pid)
                        .expect("No process to mark dead");

                    let content = String::from_utf8_lossy(&content).to_string().split("\n").map(|s|s.to_string()).collect::<Vec<_>>();
                    proc.stderr.extend_from_slice(&content);
                }
            }
        }
    }

    /// Apply a message to the current state to transform it into the new state
    /// As long as this is always called on the local state for all sent messages and on the remote state
    /// for all recieved messages -> the two states will always remain in sync
    pub fn apply_state_transform(&mut self, msg: Msg) {
        match msg {
            Msg::Continue => {
                self.status = DebuggerStatus::Running;
            }
            Msg::AddBreakpoint(b) => self.breakpoints.push(b),
            Msg::RemoveBreakpoint(baddr) => {
                let index = self
                    .breakpoints
                    .iter_mut()
                    .position(|b| b.address == baddr)
                    .expect("Failed to find bp");
                self.breakpoints.remove(index);
            }
            Msg::DoSingleStep => {}
            Msg::Restart => {}
            Msg::Stop => {}
        }
    }

    /// Send a message to the debugging client, while ensuring that any transforms are applied to the local state
    pub fn send_msg(&mut self, msg: Msg) {
        self.apply_state_transform(msg.clone());
        self.sender.as_ref().unwrap().send(msg).expect("Failed to send");
    }
}
