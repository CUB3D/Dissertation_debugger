use std::collections::HashMap;
use crate::{Breakpoint, Process, Ptrace};

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
    SpawnChild,
    /// A trap has been hit
    Trap,
}

pub struct EventDrivenPtraceDebugger {
    pub debugger: Ptrace,
    pub in_syscall: HashMap<Process, bool>,
    pub breakpoints: Vec<Breakpoint>,
}

impl EventDrivenPtraceDebugger {
    pub fn new(binary: &str, proc_name: &str, arg: &str) -> Self {
        Self {
            debugger: Ptrace::new(binary, proc_name, &[arg]).expect("Failed to start debugger"),
            in_syscall: Default::default(),
            breakpoints: Default::default(),
        }
    }

    pub fn start(&mut self) -> Process {
        let child = self.debugger.inital_spawn_child();
        child
    }

    pub fn wait_for_event(&mut self, events: &mut Vec<PtraceEvent>) -> Process {
        let in_syscall = &mut self.in_syscall;

        let (pid, status) = Process::wait_any();

        if status.wifstopped() {
            // Handle the various trap types
            let stopsig = status.wstopsig();
            if stopsig == (libc::SIGTRAP | 0x80) {
                if !in_syscall.get(&pid).unwrap_or(&false) {
                    events.push(PtraceEvent::SyscallEnter);
                    in_syscall.insert(pid, true);
                } else {
                    pid.ptrace_syscall();
                    in_syscall.insert(pid, false);
                    events.push(PtraceEvent::SyscallExit);
                    return pid;
                }
            } else if stopsig == libc::SIGTRAP {
                let event = status.0 >> 16;

                if event == 0 {
                    // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                    let user_regs = pid.ptrace_getregs();
                    if pid.ptrace_peektext(user_regs.ip as usize - 1) & 0xFF == 0xCC {
                        let bp = self.breakpoints
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
                        events.push(PtraceEvent::BreakpointHit(*bp));
                    } else {
                        events.push(PtraceEvent::Trap);
                    }
                } else {
                    match event {
                        libc::PTRACE_EVENT_FORK => {
                            events.push(PtraceEvent::SpawnChild);
                        }
                        libc::PTRACE_EVENT_VFORK => {
                            events.push(PtraceEvent::SpawnChild);
                        }
                        libc::PTRACE_EVENT_CLONE => {
                            events.push(PtraceEvent::SpawnChild);
                        }
                        libc::PTRACE_EVENT_EXIT => {
                            let exit_status = pid.ptrace_geteventmsg();
                            events.push(PtraceEvent::Exit(exit_status as isize));
                        }
                        _ => panic!("Unknown ptrace event: {}", event),
                    }
                }
            } else {
                events.push(PtraceEvent::Exit(-stopsig as isize));
            }
        }

        pid
    }
}
