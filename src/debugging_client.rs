//! A client for debugging a given process, handles process spawning and event handling for a given platform

pub trait DebuggingClient {
    //TODO: should this return an instance of the client
    fn start(&mut self, binary_path: &str) -> (std::sync::mpsc::Sender<Msg>, std::sync::mpsc::Receiver<DebuggerMsg>);
}

use ptrace::{Breakpoint, FpRegs, Process, UserRegs};

#[cfg(target_os = "windows")]
pub use win::WindowsNTDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "linux")]
pub use linux::LinuxPtraceDebuggingClient as NativeDebuggingClient;

pub enum Msg {
    Start,
    Continue,
    SingleStep(bool),
    AddBreakpoint(Breakpoint),
    /// Install the breakpoint that has already been added at the given address
    InstallBreakpoint { address: usize },
    DoSingleStep,
}

#[derive(Clone, Debug)]
pub enum DebuggerMsg {
    /// The child has hit a singlestep breakpoint, control returned to caller
    Trap {
        user_regs: Box<UserRegs>,
        fp_regs: Box<FpRegs>,
    },
    /// The child has hit a int3 breakpoint, control returned to caller
    BPTrap {
        user_regs: Box<UserRegs>,
        fp_regs: Box<FpRegs>,
        breakpoint: Breakpoint,
    },
    /// The child has hit a syscall breakpoint, control returned to caller
    SyscallTrap {
        user_regs: Box<UserRegs>,
        fp_regs: Box<FpRegs>,
    },
    /// The process has spawned
    ProcessSpwn(Process),
}


#[cfg(target_os = "linux")]
pub mod linux {
    use crate::debugging_client::DebuggingClient;
    use std::collections::HashMap;
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult};
    use imgui::{im_str, StyleColor, Window};
    use libc::user;
    use ptrace::{Breakpoint, BreakpointAction, Event, FpRegs, Process, Ptrace, UserRegs};
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::iter::Iterator;
    use std::ops::ControlFlow::Break;
    use std::time::Duration;
    use gimli::EndianSlice;
    use crate::debugging_client::{DebuggerMsg, Msg};

    #[derive(Default)]
    pub struct LinuxPtraceDebuggingClient {}

    impl DebuggingClient for LinuxPtraceDebuggingClient {
        fn start(&mut self, binary_path: &str) -> (std::sync::mpsc::Sender<Msg>, std::sync::mpsc::Receiver<DebuggerMsg>) {
            let (send_from_debug, rec_from_debug) = std::sync::mpsc::channel();
            let (sender, reciever) = std::sync::mpsc::channel();

            // Can't send a ref to a thread
            let binary_path = binary_path.to_string();
            std::thread::spawn(move || {
                let mut debugger =
                    Ptrace::new(&binary_path, "Debuggee", "").expect("Failed to start process under ptrace");

                let msg = reciever.recv().expect("failed to get msg");
                match msg {
                    Msg::Start => {
                        let child = debugger.inital_spawn_child();

                        let mut local_debugger_state = crate::debugger_ui::DebuggerState::default();

                        // let mut bp = Breakpoint::new(0x00005555555551b8);
                        // bp.install(child);

                        send_from_debug
                            .send(DebuggerMsg::ProcessSpwn(child))
                            .expect("Send proc");

                        child.ptrace_singlestep();

                        let mut is_singlestep = false;
                        let mut in_syscall = false;

                        loop {
                            let status = child.wait_for();

                            if status.wifstopped() {
                                let stopsig = status.wstopsig();
                                if stopsig == (libc::SIGTRAP | 0x80) {
                                    if !in_syscall {
                                        send_from_debug.send(DebuggerMsg::SyscallTrap {
                                            user_regs: child.ptrace_getregs(),
                                            fp_regs: child.ptrace_getfpregs(),
                                        })
                                            .expect("Faeild to send from debug");
                                    } else {
                                        child.ptrace_syscall();
                                        in_syscall = false;
                                        continue;
                                    }
                                    in_syscall = !in_syscall;
                                    // println!("syscall");
                                } else if stopsig == libc::SIGTRAP {
                                    // println!("sigtrap");
                                    let event = status.0 >> 16;

                                    let mut regs = child.ptrace_getregs();

                                    if event == 0 {
                                        // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                                        if child.ptrace_peektext(regs.ip as usize - 1)
                                            & 0xFF
                                            == 0xCC
                                        {
                                            println!(
                                                "Hit a breakpoint @ 0x{:x} ::: {:X}",
                                                regs.ip,
                                                child.ptrace_peektext(
                                                    regs.ip as usize - 1
                                                )
                                            );
                                            let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == regs.ip as usize - 1).expect("Hit a breakpoint, but we can't find it to uninstall");
                                            bp.uninstall(child);
                                            // Go back to the start of the original instruction so it actually gets executed
                                            unsafe { libc::ptrace(libc::PTRACE_POKEUSER, child, 8 * libc::RIP, regs.ip - 1) };
                                            regs.ip -= 1;

                                            //TODO: Testing, we shouldnt step after removing the bp so that the state can be seen before the bp
                                            // child.ptr/ace_singlestep();
                                            // child.wait_for();
                                            // bp.install(child);
                                            // TODO: Testing

                                            send_from_debug
                                                .send(DebuggerMsg::BPTrap {
                                                    user_regs: regs,
                                                    fp_regs: child.ptrace_getfpregs(),
                                                    breakpoint: *bp,
                                                })
                                                .expect("Faeild to send from debug");
                                        } else {
                                            send_from_debug
                                                .send(DebuggerMsg::Trap {
                                                    user_regs: regs,
                                                    fp_regs: child.ptrace_getfpregs(),
                                                })
                                                .expect("Faeild to send from debug");
                                        }
                                    }
                                }
                            }

                            loop {
                                match reciever.recv().expect("No continue") {
                                    Msg::Continue => break,
                                    Msg::SingleStep(s) => is_singlestep = s,
                                    Msg::AddBreakpoint(bp) => {
                                        local_debugger_state.breakpoints.push(bp);
                                        let bp = local_debugger_state.breakpoints.last_mut().unwrap();
                                        let success = bp.install(child);
                                        println!("Installed bp at {:?}, success: {}", bp, success);
                                    },
                                    Msg::DoSingleStep => {
                                        child.ptrace_singlestep();
                                        child.wait_for();
                                    }
                                    Msg::InstallBreakpoint { address } => {
                                        let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == address).expect("Attempt to install breakpoint that has not been added");
                                        bp.install(child);
                                    }
                                    _ => panic!("unexpected msg"),
                                }
                            }

                            if is_singlestep {
                                child.ptrace_singlestep();
                            } else {
                                child.ptrace_syscall();
                            }
                        }
                    }
                    _ => {}
                }
            });

            return (sender, rec_from_debug);
        }
    }
}

#[cfg(target_os = "windows")]
pub mod win {
    use windows::Win32::Foundation::PSTR;
    use crate::debugging_client::DebuggingClient;
    use core::default::Default;

    pub struct WindowsNTDebuggingClient {}

    impl DebuggingClient for WindowsNTDebuggingClient {
        fn start() {
            unsafe {
                let mut si = Box::<::windows::Win32::System::Threading::STARTUPINFOA>::new_zeroed().assume_init();
                let mut pi = Box::<::windows::Win32::System::Threading::PROCESS_INFORMATION>::new_zeroed().assume_init();
                ::windows::Win32::System::Threading::CreateProcessA(PSTR::default(),PSTR(b"test.exe\0".as_ptr() as _), core::ptr::null_mut(), core::ptr::null_mut(), false, 0, core::ptr::null_mut(), PSTR::default(), si.as_mut(), pi.as_mut());
            }
        }
    }
}
