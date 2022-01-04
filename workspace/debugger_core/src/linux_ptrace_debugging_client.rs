//! A debugging client for linux, based on the ptrace() API

use crate::DebuggingClient;
use crate::{DebuggerMsg, Msg};
use crate::types::{CallStack, StackFrame};
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

use ptrace::{Process, Ptrace};


use std::iter::Iterator;
use std::ops::Range;

use crate::types::{MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions};
use crate::types::{Syscall, SyscallArg};
use crate::DebuggerState;
use unwind::{Accessors, AddressSpace, Byteorder, Cursor as StackCursor, PTraceState, RegNum};

#[derive(Default)]
pub struct LinuxPtraceDebuggingClient {}

impl LinuxPtraceDebuggingClient {
    //TODO: idea: make this struct repr(c) then we can cast easily
    fn convert_ptrace_registers(
        oregs: &Box<ptrace::UserRegs>,
    ) -> Box<crate::types::UserRegs> {
        let mut regs = Box::<crate::types::UserRegs>::default();
        regs.ax = oregs.ax;
        regs.bx = oregs.bx;
        regs.cx = oregs.cx;
        regs.dx = oregs.dx;

        regs.bp = oregs.bp;
        regs.sp = oregs.sp;
        regs.si = oregs.si;
        regs.di = oregs.di;

        regs.r8 = oregs.r8;
        regs.r9 = oregs.r9;
        regs.r10 = oregs.r10;
        regs.r11 = oregs.r11;
        regs.r12 = oregs.r12;
        regs.r13 = oregs.r13;
        regs.r14 = oregs.r14;
        regs.r15 = oregs.r15;

        regs.ip = oregs.ip;

        regs.flags = oregs.flags;

        regs.orig_ax = oregs.orig_ax;

        regs.gs = oregs.gs;
        regs.fs = oregs.fs;
        regs.ds = oregs.ds;
        regs.cs = oregs.cs;
        regs.ss = oregs.ss;

        regs
    }

    fn get_memory(pid: Process) -> Vec<(Vec<u8>, Range<usize>)> {
        let mut memory = Vec::new();
        if let Some(mmap) = ptrace::get_memory_map(pid.0) {
            let mut mem_file = std::fs::File::open(format!("/proc/{}/mem", pid.0)).expect("No mem?");
            for ent in &mmap.0 {
                // Only backup memory that we can read
                if !ent.permissions.read {
                    continue;
                }
                // println!("Backing up mem section: {}", ent.path);
                let mut mem = vec![0u8; ent.range.end - ent.range.start];
                mem_file.seek(SeekFrom::Start(ent.range.start as u64)).expect("Seek failed");
                //TODO:
                let _ = mem_file.read_exact(&mut mem);//.expect("Failed to read memory range");

                memory.push((mem, ent.range.clone()));
            }

            return memory;
        }

        return vec![];
    }

    fn get_memory_map(pid: Process) -> Option<MemoryMap> {
        if let Some(mmap) = ptrace::get_memory_map(pid.0) {
            let mmap = MemoryMap(
                mmap.0
                    .iter()
                    .map(|mp| MemoryMapEntry {
                        path: mp.path.clone(),
                        range: mp.range.clone(),
                        permissions: MemoryMapEntryPermissions {
                            read: mp.permissions.read,
                            write: mp.permissions.write,
                            execute: mp.permissions.execute,
                            kind: match mp.permissions.kind {
                                ptrace::MemoryMapEntryPermissionsKind::Private => {
                                    crate::types::MemoryMapEntryPermissionsKind::Private
                                }
                                ptrace::MemoryMapEntryPermissionsKind::Shared => {
                                    crate::types::MemoryMapEntryPermissionsKind::Shared
                                }
                            },
                        },
                    })
                    .collect(),
            );

            return Some(mmap);
        }
        None
    }

    /// Unwind the call stack for the given process
    fn get_call_stack(pid: Process) -> Result<CallStack, Box<dyn Error>> {
        let mut call_stack = Vec::new();

        let state = PTraceState::new(pid.0 as u32)?;
        let space = AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT)?;
        let mut cursor = StackCursor::remote(&space, &state)?;
        loop {
            let ip = cursor.register(RegNum::IP)?;

            match (cursor.procedure_info(), cursor.procedure_name()) {
                (Ok(ref info), Ok(ref name)) if ip == info.start_ip() + name.offset() => {
                    call_stack.push(StackFrame {
                        addr: ip as usize,
                        description: format!(
                            "{} ({:#016x}) + {:#x}",
                            name.name(),
                            info.start_ip(),
                            name.offset()
                        ),
                    });
                }
                _ => call_stack.push(StackFrame {
                    addr: ip as usize,
                    description: "????".to_string(),
                }),
            }

            if !cursor.step()? {
                break;
            }
        }

        Ok(CallStack(call_stack))
    }

    /// Convert the register state from a syscall trap into a syscall event for the ui
    fn get_syscall_description(pid: Process, user_regs: &Box<ptrace::UserRegs>) -> Syscall {
        macro_rules! syscall {
                ($name: expr) => {
                        return Syscall {
                            name: $name.to_string(),
                            args: vec![]
                        }
                };

                ($name: expr, $($x:ident),+) => {
                        return Syscall {
                            name: $name.to_string(),
                            args: syscall!(@arg, $($x),+ )
                        }
                };

                (@arg, $x: ident) => {
                    vec![syscall!(@arg_type, $x, user_regs.di)]
                };

                (@arg, $x: ident, $y: ident) => {
                    vec![syscall!(@arg_type, $x, user_regs.di), syscall!(@arg_type, $y, user_regs.si)]
                };

                (@arg, $x: ident, $y: ident, $z: ident) => {
                    vec![syscall!(@arg_type, $x, user_regs.di), syscall!(@arg_type, $y, user_regs.si), syscall!(@arg_type, $z, user_regs.dx)]
                };

                (@arg, $x: ident, $y: ident, $z: ident, $a: ident) => {
                    vec![syscall!(@arg_type, $x, user_regs.di), syscall!(@arg_type, $y, user_regs.si), syscall!(@arg_type, $z, user_regs.dx), syscall!(@arg_type, $a, user_regs.r10)]
                };

                (@arg, $x: ident, $y: ident, $z: ident, $a: ident, b: ident) => {
                    vec![syscall!(@arg_type, $x, user_regs.di), syscall!(@arg_type, $y, user_regs.si), syscall!(@arg_type, $z, user_regs.dx), syscall!(@arg_type, $a, user_regs.r10), syscall!(@arg_type, $b, user_regs.r8)]
                };

                (@arg, $x: ident, $y: ident, $z: ident, $a: ident, $b: ident, $c: ident) => {
                    vec![syscall!(@arg_type, $x, user_regs.di), syscall!(@arg_type, $y, user_regs.si), syscall!(@arg_type, $z, user_regs.dx), syscall!(@arg_type, $a, user_regs.r10), syscall!(@arg_type, $b, user_regs.r8), syscall!(@arg_type, $b, user_regs.r9)]
                };

                (@arg_type, u64, $value: expr) => {
                    SyscallArg::U64($value)
                };

                (@arg_type, addr, $value: expr) => {
                    SyscallArg::Address($value)
                };

                (@arg_type, filedesc, $value: expr) => {
                    SyscallArg::FileDescriptor($value as i64)
                };

                (@arg_type, pid, $value: expr) => {
                    SyscallArg::ProcessId($value as u64)
                };

                (@arg_type, filepath, $value: expr) => {
                    SyscallArg::FilePath(unsafe { pid.read_string($value as i64) })
                };

                (@arg_type, string, $value: expr) => {
                    SyscallArg::String(unsafe { pid.read_string($value as i64) })
                };
            }

        match user_regs.orig_ax as libc::c_long {
            libc::SYS_read => syscall!("read", u64, addr, u64),
            libc::SYS_brk => syscall!("brk", u64),
            libc::SYS_truncate => syscall!("truncate", filepath),
            libc::SYS_recvfrom => syscall!("recvfrom", filedesc, addr, u64, u64, addr, addr),
            libc::SYS_dup => syscall!("dup", filedesc),
            libc::SYS_dup2 => syscall!("dup2", filedesc, filedesc),
            libc::SYS_lgetxattr => syscall!("lgetxattr", filepath, string, addr, u64),
            libc::SYS_access => syscall!("access", filepath, u64),
            libc::SYS_arch_prctl => syscall!("arch_prctl", u64, addr),
            libc::SYS_close => syscall!("close", filedesc),
            libc::SYS_exit_group => syscall!("exit_group", u64),
            libc::SYS_newfstatat => syscall!("newfsstatat", filedesc, filepath, addr, u64),
            libc::SYS_munmap => syscall!("newfsstatat", addr, u64),
            libc::SYS_preadv => syscall!("preadv", filedesc, addr, u64, u64),
            libc::SYS_pread64 => syscall!("pread64", filedesc, addr, u64, u64),
            libc::SYS_mprotect => syscall!("mprotect", addr, u64, u64),
            libc::SYS_mmap => syscall!("mmap", addr, u64, u64, u64, filedesc, u64),
            libc::SYS_write => syscall!("write", filedesc, addr, u64),
            libc::SYS_read => syscall!("read", filedesc, addr, u64),
            libc::SYS_set_tid_address => syscall!("set_tid_address", addr),
            libc::SYS_set_robust_list => syscall!("set_robust_list", addr, u64),
            libc::SYS_rt_sigaction => syscall!("rt_sigaction", u64, addr, addr),
            libc::SYS_rt_sigprocmask => syscall!("rt_sigprocmask", u64, addr, addr),
            libc::SYS_prlimit64 => syscall!("prlimit64", pid, u64, addr, addr),
            libc::SYS_getpid => syscall!("getpid"),
            libc::SYS_clock_nanosleep => syscall!("clock_nanosleep", u64, u64, addr, addr),
            // libc::SYS_clone => syscall!("clone", addr, addr, u64, addr, addr, addr, addr),
            libc::SYS_openat => {
                let fd_name = match user_regs.di as i32 {
                    -100 => "AT_FDCWD".to_string(),
                    _ => format!("{}", user_regs.di),
                };
                let path = unsafe { pid.read_string(user_regs.si as i64) };

                return Syscall {
                    name: "openat".to_string(),
                    args: vec![
                        SyscallArg::String(fd_name),
                        SyscallArg::FilePath(path),
                        SyscallArg::U64(user_regs.dx),
                    ],
                };
            }
            _ => {
                panic!("Unknown syscall {}",  user_regs.orig_ax);
            }
        }
    }

    // Run the ptrace event loop
    // Waits for signals from the process and responds appropriately
}

impl DebuggingClient for LinuxPtraceDebuggingClient {
    fn start(&mut self, binary_path: &str, args: &[&str]) -> (Sender<Msg>, Receiver<DebuggerMsg>) {
        let (send_from_debug, rec_from_debug) = unbounded();
        let (sender, reciever) = unbounded();

        // Can't send a ref to a thread
        let binary_path = binary_path.to_string();
        let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        std::thread::spawn(move || {
            let farg = args.first().map(|s| s.clone()).unwrap_or("".to_string());
            let debugger = Ptrace::new(&binary_path, "Debuggee", &farg)
                .expect("Failed to start process under ptrace");

            let msg = reciever.recv().expect("failed to get msg");
            match msg {
                Msg::Start => {
                    let child = debugger.inital_spawn_child();

                    let mut local_debugger_state = DebuggerState::default();

                    send_from_debug
                        .send(DebuggerMsg::ProcessSpawn(child))
                        .expect("Send proc");

                    child.ptrace_singlestep();

                    let mut is_singlestep = false;
                    let mut in_syscall = HashMap::<Process, bool>::new();

                    drop(child);

                    'big_exit: loop {
                        let (pid, status) = Process::wait_any();

                        if status.wifstopped() {
                            // If we can get a call stack, forward that to the ui
                            if let Ok(call_stack) =
                            LinuxPtraceDebuggingClient::get_call_stack(pid)
                            {
                                send_from_debug.send(DebuggerMsg::CallStack(pid, call_stack));
                            }

                            // If we can get a memory map for the process
                            if let Some(mmap) = LinuxPtraceDebuggingClient::get_memory_map(pid)
                            {
                                send_from_debug.send(DebuggerMsg::MemoryMap(pid, mmap));
                            }

                            let mut user_regs = pid.ptrace_getregs();
                            let fp_regs = pid.ptrace_getfpregs();

                            let user_regs_ui =
                                LinuxPtraceDebuggingClient::convert_ptrace_registers(
                                    &user_regs,
                                );
                            send_from_debug
                                .send(DebuggerMsg::UserRegisters(pid, user_regs_ui.clone()));
                            send_from_debug
                                .send(DebuggerMsg::FpRegisters(pid, fp_regs.clone()));

                            let memory = LinuxPtraceDebuggingClient::get_memory(pid);
                            send_from_debug
                                .send(DebuggerMsg::Memory(pid, memory));

                            // Handle the various trap types
                            let stopsig = status.wstopsig();
                            if stopsig == (libc::SIGTRAP | 0x80) {
                                //TODO: do we need to track this for each process?
                                if !in_syscall.get(&pid).unwrap_or(&false) {
                                    // Figure out the details of the syscall
                                    let syscall_desc =
                                        LinuxPtraceDebuggingClient::get_syscall_description(
                                            pid, &user_regs,
                                        );
                                    send_from_debug.send(DebuggerMsg::Syscall(pid, syscall_desc));
                                    send_from_debug
                                        .send(DebuggerMsg::SyscallTrap)
                                        .expect("Failed to send from debug");
                                    in_syscall.insert(pid, true);
                                } else {
                                    pid.ptrace_syscall();
                                    in_syscall.insert(pid, false);
                                    continue;
                                }
                                // println!("syscall");
                            } else if stopsig == libc::SIGTRAP {
                                // println!("sigtrap");
                                let event = status.0 >> 16;


                                if event == 0 {
                                    // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                                    if pid.ptrace_peektext(user_regs.ip as usize - 1) & 0xFF == 0xCC
                                    {
                                        // println!(
                                        //     "Hit a breakpoint @ 0x{:x} ::: {:X}",
                                        //     user_regs.ip,
                                        //     pid.ptrace_peektext(user_regs.ip as usize - 1)
                                        // );
                                        let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == user_regs.ip as usize - 1).expect("Hit a breakpoint, but we can't find it to uninstall");
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
                                        user_regs.ip -= 1;
                                        let user_regs_ui =
                                            LinuxPtraceDebuggingClient::convert_ptrace_registers(
                                                &user_regs,
                                            );
                                        send_from_debug
                                            .send(DebuggerMsg::UserRegisters(pid, user_regs_ui.clone()));

                                        send_from_debug
                                            .send(DebuggerMsg::BPTrap { breakpoint: *bp })
                                            .expect("Faeild to send from debug");
                                    } else {
                                        send_from_debug
                                            .send(DebuggerMsg::Trap)
                                            .expect("Faeild to send from debug");
                                    }
                                } else {
                                    match event {
                                        libc::PTRACE_EVENT_FORK => {
                                            let pid = pid.ptrace_geteventmsg();
                                            unsafe {
                                                libc::ptrace(
                                                    libc::PTRACE_SETOPTIONS,
                                                    pid,
                                                    0,
                                                    libc::PTRACE_O_TRACEVFORK
                                                        | libc::PTRACE_O_EXITKILL
                                                        | libc::PTRACE_O_TRACECLONE
                                                        | libc::PTRACE_O_TRACEEXEC
                                                        | libc::PTRACE_O_TRACEEXIT
                                                        | libc::PTRACE_O_TRACEFORK
                                                        | libc::PTRACE_O_TRACESYSGOOD,
                                                )
                                            };
                                            // self.processes.insert(pid as i32, ());
                                            println!("Child forked {}", pid);
                                            Process(pid as i32).ptrace_syscall();
                                        }
                                        libc::PTRACE_EVENT_VFORK => {
                                            let pid = pid.ptrace_geteventmsg();
                                            unsafe {
                                                libc::ptrace(
                                                    libc::PTRACE_SETOPTIONS,
                                                    pid,
                                                    0,
                                                    libc::PTRACE_O_TRACEVFORK
                                                        | libc::PTRACE_O_EXITKILL
                                                        | libc::PTRACE_O_TRACECLONE
                                                        | libc::PTRACE_O_TRACEEXEC
                                                        | libc::PTRACE_O_TRACEEXIT
                                                        | libc::PTRACE_O_TRACEFORK
                                                        | libc::PTRACE_O_TRACESYSGOOD,
                                                )
                                            };
                                            // self.processes.insert(pid as i32, ());
                                            println!("Child vforked {}", pid);
                                            Process(pid as i32).ptrace_syscall();
                                        }
                                        libc::PTRACE_EVENT_CLONE => {
                                            let pid = pid.ptrace_geteventmsg();
                                            unsafe {
                                                libc::ptrace(
                                                    libc::PTRACE_SETOPTIONS,
                                                    pid,
                                                    0,
                                                    libc::PTRACE_O_TRACEVFORK
                                                        | libc::PTRACE_O_EXITKILL
                                                        | libc::PTRACE_O_TRACECLONE
                                                        | libc::PTRACE_O_TRACEEXEC
                                                        | libc::PTRACE_O_TRACEEXIT
                                                        | libc::PTRACE_O_TRACEFORK
                                                        | libc::PTRACE_O_TRACESYSGOOD,
                                                )
                                            };
                                            send_from_debug.send(
                                                DebuggerMsg::ChildProcessSpawn(Process(
                                                    pid as i32,
                                                )),
                                            );
                                            println!("Child cloned {}", pid);
                                        }
                                        libc::PTRACE_EVENT_EXIT => {
                                            let exit_status = pid.ptrace_geteventmsg();
                                            println!(
                                                "child {:?} exit with status {}, assuming finished",
                                                pid, exit_status
                                            );
                                            send_from_debug.send(
                                                DebuggerMsg::ProcessDeath(pid, exit_status),
                                            );
                                            break 'big_exit;
                                            // self.processes.remove(&pid.0);
                                            // std::process::exit(0);
                                        }
                                        _ => panic!("Unknown ptrace event: {}", event),
                                    }
                                }
                            }
                        }

                        loop {
                            let msg = reciever.recv().expect("No continue");
                            local_debugger_state.apply_state_transform(msg.clone());
                            match msg {
                                Msg::Continue => break,
                                Msg::SingleStep(s) => is_singlestep = s,
                                Msg::AddBreakpoint(_bp) => {
                                    let bp =
                                        local_debugger_state.breakpoints.last_mut().unwrap();
                                    let success = bp.install(child);
                                    // println!("Installed bp at {:?}, success: {}", bp, success);
                                }
                                Msg::DoSingleStep => {
                                    pid.ptrace_singlestep();
                                    pid.wait_for();
                                }
                                Msg::InstallBreakpoint { address } => {
                                    let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == address).expect("Attempt to install breakpoint that has not been added");
                                    bp.install(child);
                                }
                                Msg::RemoveBreakpoint(baddr) => {
                                    let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == baddr).expect("Attempt to remove breakpoint that has not been added");
                                    bp.uninstall(child);
                                }
                                Msg::Start => {panic!("Unexpected start msg")}
                                Msg::Restart => {
                                    panic!("Unimplemented: restart msg");
                                }
                                Msg::Stop => {
                                    child.sigstop();
                                    // panic!("Unimplemented: stop msg");
                                }
                            }
                        }

                        if is_singlestep {
                            pid.ptrace_singlestep();
                        } else {
                            pid.ptrace_syscall();
                        }
                    }
                }
                _ => {}
            }
        });

        return (sender, rec_from_debug);
    }
}
