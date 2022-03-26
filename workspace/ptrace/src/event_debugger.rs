use crate::{Breakpoint, Process, Ptrace};
use std::collections::HashMap;

/// Events that can be emitted during debugging a process
#[derive(Debug, Clone)]
pub enum PtraceEvent {
    /// A breakpoint has been hit
    BreakpointHit(Breakpoint),
    /// Syscall enter
    SyscallEnter,
    /// Syscall exit
    SyscallExit,
    /// The process has exited with the given status
    Exit(isize),
    /// A child process has been spawned
    SpawnChild(Process),
    /// A trap has been hit
    Trap,
}

pub struct EventDrivenPtraceDebugger {
    pub debugger: Ptrace,
    pub in_syscall: HashMap<Process, bool>,
    pub breakpoints: Vec<Breakpoint>,
    pub processes: Vec<Process>,
}

impl EventDrivenPtraceDebugger {
    pub fn new(binary: &str, proc_name: &str, arg: &str) -> Self {
        Self {
            debugger: Ptrace::new(binary, proc_name, &[arg]).expect("Failed to start debugger"),
            in_syscall: Default::default(),
            processes: Default::default(),
            breakpoints: Default::default(),
        }
    }

    /// Start the process for debugging, will start in a paused state as per Ptrace::inital_spawn_child
    /// Callback is invoked just before execveing the new child process
    /// If already debugging a process this will clear our any existing state and breakpoints so that
    /// only events for the new child are received
    pub fn start<F: FnOnce()>(&mut self, child_callback: Option<F>) -> Process {
        self.processes.clear();
        self.in_syscall.clear();
        self.breakpoints.clear();

        let child = self.debugger.inital_spawn_child(child_callback);

        self.processes.push(child);
        child
    }

    pub fn wait_for_event(&mut self) -> (Process, PtraceEvent) {
        let in_syscall = &mut self.in_syscall;

        // Wait for a process thats in our process list
        // If its not in the list its probably from an old instance
        let (pid, status) = loop {
            let (pid, status) = Process::wait_any();
            if self.processes.contains(&pid) {
                break (pid, status);
            }
        };

        if status.wifstopped() {
            // Handle the various trap types
            let stopsig = status.wstopsig();
            if stopsig == (libc::SIGTRAP | 0x80) {
                if !in_syscall.get(&pid).unwrap_or(&false) {
                    in_syscall.insert(pid, true);
                    return (pid, PtraceEvent::SyscallEnter);
                } else {
                    // pid.ptrace_syscall();
                    in_syscall.insert(pid, false);
                    return (pid, PtraceEvent::SyscallExit);
                }
            } else if stopsig == libc::SIGTRAP {
                let event = status.0 >> 16;

                if event == 0 {

                    #[cfg(target_arch = "x86_64")]
                    {
                        // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                        let user_regs = pid.ptrace_getregs();
                        if pid.ptrace_peektext(user_regs.ip as usize - 1) & 0xFF == 0xCC {
                            let bp = self
                                .breakpoints
                                .iter_mut()
                                .find(|bp| bp.address == user_regs.ip as usize - 1)
                                .expect("Hit a breakpoint, but we can't find it to uninstall");
                            bp.uninstall(pid);
                            // Go back to the start of the original instruction so it actually gets executed
                            unsafe {
                                libc::ptrace(
                                    libc::PTRACE_POKEUSER,
                                    pid,
                                    8 * libc::RIP,
                                    user_regs.ip - 1,
                                )
                            };
                            return (pid, PtraceEvent::BreakpointHit(*bp));
                        } else {
                            return (pid, PtraceEvent::Trap);
                        }
                    }

                    #[cfg(target_arch = "aarch64")]
                    {
                        // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                        let mut user_regs = pid.ptrace_getregs();
                        if pid.ptrace_peektext(user_regs.pc as usize) & 0xFFFFFFFF == 0xD4200000 {
                            let bp = self
                                .breakpoints
                                .iter_mut()
                                .find(|bp| bp.address == user_regs.pc as usize)
                                .expect("Hit a breakpoint, but we can't find it to uninstall");
                            bp.uninstall(pid);

                            // Go back to the start of the original instruction so it actually gets executed
                            user_regs.pc -= 4;
                            pid.ptrace_setregs(&mut user_regs);

                            return (pid, PtraceEvent::BreakpointHit(*bp));
                        } else {
                            return (pid, PtraceEvent::Trap);
                        }
                    }
                } else {
                    match event {
                        libc::PTRACE_EVENT_FORK => {
                            let child_pid = pid.ptrace_geteventmsg();
                            let child_pid = Process(child_pid as i32);
                            self.processes.push(child_pid);
                            return (pid, PtraceEvent::SpawnChild(child_pid));
                        }
                        libc::PTRACE_EVENT_VFORK => {
                            let child_pid = pid.ptrace_geteventmsg();
                            let child_pid = Process(child_pid as i32);
                            self.processes.push(child_pid);
                            return (pid, PtraceEvent::SpawnChild(child_pid));
                        }
                        libc::PTRACE_EVENT_CLONE => {
                            let child_pid = pid.ptrace_geteventmsg();
                            let child_pid = Process(child_pid as i32);
                            self.processes.push(child_pid);
                            return (pid, PtraceEvent::SpawnChild(child_pid));
                        }
                        libc::PTRACE_EVENT_EXIT => {
                            let exit_status = pid.ptrace_geteventmsg();
                            if let Some(child_pos) =
                                self.processes.iter().position(|child| *child == pid)
                            {
                                self.processes.remove(child_pos);
                            }
                            return (pid, PtraceEvent::Exit(exit_status as isize));
                        }
                        _ => panic!("Unknown ptrace event: {}", event),
                    }
                }
            } else {
                return (pid, PtraceEvent::Exit(-stopsig as isize));
            }
        } else {
            panic!("child !stopped");
        }
    }
}
