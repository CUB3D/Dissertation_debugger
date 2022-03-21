//! A debugging client for linux, based on the ptrace() API

use crate::types::{CallStack, StackFrame};
use crate::DebuggingClient;
use crate::{DebuggerMsg, Msg};
use crossbeam_channel::{unbounded, Receiver, Sender};

use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

use ptrace::{Process};

use std::iter::Iterator;
use std::ops::Range;
use std::sync::{Arc, RwLock};


use crate::types::{MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions};
use crate::types::{Syscall, SyscallArg};

use ptrace::event_debugger::{EventDrivenPtraceDebugger, PtraceEvent};
use unwind::{Accessors, AddressSpace, Byteorder, Cursor as StackCursor, PTraceState, RegNum};

#[derive(Default)]
pub struct LinuxPtraceDebuggingClient {}

impl LinuxPtraceDebuggingClient {
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

    #[cfg(target_arch = "aarch64")]
    fn convert_ptrace_registers(oregs: &Box<ptrace::UserRegs>) -> Box<crate::types::UserRegs> {
        let mut regs = Box::<crate::types::UserRegs>::default();
        regs
    }

    #[cfg(target_arch = "x86_64")]
    //TODO: idea: make this struct repr(c) then we can cast easily
    fn convert_ptrace_registers(oregs: &Box<ptrace::UserRegs>) -> Box<crate::types::UserRegs> {
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
            let mut mem_file =
                std::fs::File::open(format!("/proc/{}/mem", pid.0)).expect("No mem?");
            for ent in &mmap.0 {
                // Only backup memory that we can read
                if !ent.permissions.read {
                    continue;
                }
                // println!("Backing up mem section: {}", ent.path);
                let mut mem = vec![0u8; ent.range.end - ent.range.start];
                mem_file
                    .seek(SeekFrom::Start(ent.range.start as u64))
                    .expect("Seek failed");
                //TODO:
                let _ = mem_file.read_exact(&mut mem); //.expect("Failed to read memory range");

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

    #[cfg(target_arch = "aarch64")]
    fn get_syscall_description(pid: Process, user_regs: &Box<ptrace::UserRegs>) -> Syscall {
        Syscall {
            name: "Unknown".to_string(),
            args: vec![]
        }
    }

    #[cfg(target_arch = "x86_64")]
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
            libc::SYS_lseek => syscall!("lssek", filedesc, u64, u64),
            libc::SYS_futex => syscall!("futex", u64, u64, u64, u64, u64, u64),
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
                eprintln!("Unknown syscall {}", user_regs.orig_ax);
                return Syscall {
                    name: format!("UNKNOWN<{}>", user_regs.orig_ax),
                    args: vec![],
                };
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

        //TODO: massive hack, pls no
        let control_messages: Arc<RwLock<Vec<Msg>>> = Arc::new(RwLock::new(Vec::new()));
        let state_messages: Arc<RwLock<Vec<Msg>>> = Arc::new(RwLock::new(Vec::new()));

        let control_messages_local = Arc::clone(&control_messages);
        let state_messages_local = Arc::clone(&state_messages);
        std::thread::spawn(move || loop {
            let msg = reciever.recv().expect("failed to get msg");
            match msg {
                Msg::Continue | Msg::Restart | Msg::DoSingleStep | Msg::Stop => {
                    control_messages_local.write().unwrap().push(msg);
                }
                _ => {
                    state_messages_local.write().unwrap().push(msg);
                }
            }
        });

        std::thread::spawn(move || {
            let farg = args.first().map(|s| s.clone()).unwrap_or("".to_string());

            let mut debugger = EventDrivenPtraceDebugger::new(&binary_path, "Debuggee", &farg);

            let mut child = debugger.start();

            send_from_debug
                .send(DebuggerMsg::ProcessSpawn(child))
                .expect("Send proc");

            'debug_loop: loop {
                println!("Waiting for msg");

                // Wait for first continue msg
                loop {
                    if let Some(Msg::Continue) = control_messages.write().unwrap().pop() {
                        break;
                    }
                }
                println!("Got start msg");

                let mut breakpoints_pending_reinstall = Vec::new();

                //TODO: other msgs
                while let Some(msg) = state_messages.write().unwrap().pop() {
                    println!("Got early msg {:?}", msg);
                    match msg {
                        Msg::AddBreakpoint(bp) => {
                            let mut bp = bp.clone();
                            bp.install(child);
                            debugger.breakpoints.push(bp);
                        }
                        Msg::RemoveBreakpoint(addr) => {
                            if let Some(bp) = debugger
                                .breakpoints
                                .iter_mut()
                                .find(|bp| bp.address == addr)
                            {
                                bp.uninstall(child);
                            }
                            if let Some(bp_pos) = debugger
                                .breakpoints
                                .iter_mut()
                                .position(|bp| bp.address == addr)
                            {
                                debugger.breakpoints.remove(bp_pos);
                            }
                        }
                        _ => unimplemented!("Got early state msg: {:?}", msg),
                    }
                }

                child.ptrace_syscall();

                'big_exit: loop {
                    //println!("Waiting for ptrace events");
                    let (pid, evt) = debugger.wait_for_event();
                    // println!("{:?} had an event {:?}", pid, evt);

                    // Reinstall any pending breakpoints for this thread
                    for (index, (bp_pid, address)) in breakpoints_pending_reinstall
                        .clone()
                        .iter()
                        .copied()
                        .enumerate()
                    {
                        if bp_pid != pid {
                            continue;
                        }

                        let bp = debugger
                            .breakpoints
                            .iter_mut()
                            .find(|bp| bp.address == address)
                            .expect("Attempt to install breakpoint that has not been added");
                        bp.install(bp_pid);
                        println!("After installing bp = {:?}", bp);
                        breakpoints_pending_reinstall.remove(index);
                    }

                    // Check for new state messages
                    //TODO: other msgs
                    while let Some(msg) = state_messages.write().unwrap().pop() {
                        println!("Got state msg: {:?}", msg);
                        match msg {
                            Msg::AddBreakpoint(bp) => {
                                let mut bp = bp.clone();
                                bp.install(pid);
                                debugger.breakpoints.push(bp);
                            }
                            Msg::RemoveBreakpoint(addr) => {
                                let bp = debugger
                                    .breakpoints
                                    .iter_mut()
                                    .find(|bp| bp.address == addr)
                                    .expect("Removed breakpoint that doesnt exist");
                                bp.uninstall(pid);
                                if let Some(bp_pos) = debugger
                                    .breakpoints
                                    .iter_mut()
                                    .position(|bp| bp.address == addr)
                                {
                                    debugger.breakpoints.remove(bp_pos);
                                }

                                while let Some(pos) = breakpoints_pending_reinstall
                                    .iter()
                                    .position(|(_, bp_addr)| *bp_addr == addr)
                                {
                                    breakpoints_pending_reinstall.remove(pos);
                                }
                            }
                            _ => unimplemented!("Got early state msg: {:?}", msg),
                        }
                    }

                    while let Some(msg) = control_messages.write().unwrap().pop() {
                        println!("Got ctrl msg: {:?}", msg);
                        match msg {
                            Msg::Restart => {
                                //TODO: kill the child
                                child = debugger.start();

                                breakpoints_pending_reinstall.clear();

                                send_from_debug
                                    .send(DebuggerMsg::ProcessSpawn(child))
                                    .expect("Send proc");
                                continue 'debug_loop;
                            }
                            Msg::Stop => {
                                child.sigkill();
                                child.ptrace_syscall();
                                continue 'big_exit;
                            }
                            _ => unimplemented!("Got early ctrl msg: {:?}", msg),
                        }
                    }

                    macro_rules! send_regs {
                        () => {
                            #[cfg(target_arch = "x86_64")]
                            {
                            // Try and send regs
                            let user_regs = pid.ptrace_getregs();
                            let fp_regs = pid.ptrace_getfpregs();

                            let user_regs_ui =
                                LinuxPtraceDebuggingClient::convert_ptrace_registers(&user_regs);
                            send_from_debug
                                .send(DebuggerMsg::UserRegisters(pid, user_regs_ui.clone()))
                                .expect("Send fail");
                            send_from_debug
                                .send(DebuggerMsg::FpRegisters(pid, fp_regs.clone()))
                                .expect("Send fail");
                            }
                        };
                    }

                    //println!("Got ptrace evt: {:?} @ {:?}", evt, pid);
                    match evt {
                        PtraceEvent::SyscallEnter => {
                            // If we can get a call stack, forward that to the ui
                            if let Ok(call_stack) = LinuxPtraceDebuggingClient::get_call_stack(pid)
                            {
                                send_from_debug
                                    .send(DebuggerMsg::CallStack(pid, call_stack))
                                    .expect("Send fail");
                            }

                            let user_regs = pid.ptrace_getregs();
                            // Figure out the details of the syscall
                            let syscall_desc = LinuxPtraceDebuggingClient::get_syscall_description(
                                pid, &user_regs,
                            );
                            send_from_debug
                                .send(DebuggerMsg::Syscall(pid, syscall_desc))
                                .expect("Send fail");
                            pid.ptrace_syscall();

                            continue 'big_exit;
                        }
                        PtraceEvent::SyscallExit => {
                            pid.ptrace_syscall();
                            continue 'big_exit;
                        }
                        PtraceEvent::Exit(exit_status) => {
                            // If we can get a call stack, forward that to the ui
                            if let Ok(call_stack) = LinuxPtraceDebuggingClient::get_call_stack(pid)
                            {
                                send_from_debug.send(DebuggerMsg::CallStack(pid, call_stack)).expect("Failed to send");
                            }

                            // If we can get a memory map for the process
                            if let Some(mmap) = LinuxPtraceDebuggingClient::get_memory_map(pid) {
                                send_from_debug
                                    .send(DebuggerMsg::MemoryMap(pid, mmap))
                                    .expect("Send fail");
                            }

                            // Try and send memory state
                            let memory = LinuxPtraceDebuggingClient::get_memory(pid);
                            send_from_debug
                                .send(DebuggerMsg::Memory(pid, memory))
                                .expect("Send fail");


                            println!(
                                "child {:?} exit with status {}, assuming finished",
                                pid, exit_status
                            );
                            send_from_debug
                                .send(DebuggerMsg::ProcessDeath(pid, exit_status))
                                .expect("Send fail");

                            if pid != child {
                                println!("Not parent death, continuing");
                                pid.ptrace_syscall();
                                continue 'big_exit;
                            }
                        }
                        PtraceEvent::SpawnChild(child_pid) => {
                            unsafe {
                                libc::ptrace(
                                    libc::PTRACE_SETOPTIONS,
                                    child_pid.0,
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
                            send_from_debug
                                .send(DebuggerMsg::ChildProcessSpawn(child_pid))
                                .expect("Send fail");
                            println!("Child cloned/vforked/forked {:?}", child_pid);
                            pid.ptrace_syscall();
                            child_pid.ptrace_syscall();
                            continue 'big_exit;
                        }
                        PtraceEvent::Trap => {
                            // If we can get a call stack, forward that to the ui
                            if let Ok(call_stack) = LinuxPtraceDebuggingClient::get_call_stack(pid)
                            {
                                send_from_debug.send(DebuggerMsg::CallStack(pid, call_stack)).expect("Failed to send");
                            }

                            // If we can get a memory map for the process
                            if let Some(mmap) = LinuxPtraceDebuggingClient::get_memory_map(pid) {
                                send_from_debug
                                    .send(DebuggerMsg::MemoryMap(pid, mmap))
                                    .expect("Send fail");
                            }

                            // Try and send memory state
                            let memory = LinuxPtraceDebuggingClient::get_memory(pid);
                            send_from_debug
                                .send(DebuggerMsg::Memory(pid, memory))
                                .expect("Send fail");

                            send_regs!();

                            send_from_debug
                                .send(DebuggerMsg::Trap)
                                .expect("Faeild to send from debug");
                        }
                        PtraceEvent::BreakpointHit(bp) => {
                            breakpoints_pending_reinstall.push((pid, bp.address));

                            send_from_debug
                                .send(DebuggerMsg::BPTrap { breakpoint: bp })
                                .expect("Faeild to send from debug");

                            // If we can get a call stack, forward that to the ui
                            if let Ok(call_stack) = LinuxPtraceDebuggingClient::get_call_stack(pid)
                            {
                                send_from_debug.send(DebuggerMsg::CallStack(pid, call_stack)).expect("Failed to send");
                            }

                            // If we can get a memory map for the process
                            if let Some(mmap) = LinuxPtraceDebuggingClient::get_memory_map(pid) {
                                send_from_debug
                                    .send(DebuggerMsg::MemoryMap(pid, mmap))
                                    .expect("Send fail");
                            }

                            send_regs!();

                            // Try and send memory state
                            let memory = LinuxPtraceDebuggingClient::get_memory(pid);
                            send_from_debug
                                .send(DebuggerMsg::Memory(pid, memory))
                                .expect("Send fail");
                        }
                    }

                    loop {
                        if let Some(msg) = control_messages.write().unwrap().pop() {
                            println!("Got msg: {:?}", msg);
                            match msg {
                                Msg::Continue => {
                                    break;
                                }
                                Msg::DoSingleStep => {
                                    pid.ptrace_singlestep();
                                    continue 'big_exit;
                                }
                                Msg::Restart => {
                                    //TODO: kill the child
                                    child = debugger.start();

                                    breakpoints_pending_reinstall.clear();

                                    send_from_debug
                                        .send(DebuggerMsg::ProcessSpawn(child))
                                        .expect("Send proc");
                                    continue 'debug_loop;
                                }
                                Msg::Stop => {
                                    child.sigkill();
                                    child.ptrace_syscall();
                                    continue 'big_exit;
                                }
                                _ => unimplemented!("Got control msg: {:?}", msg),
                            }
                        }
                    }

                    // Check for new state messages
                    //TODO: other msgs
                    while let Some(msg) = state_messages.write().unwrap().pop() {
                        println!("Got state msg: {:?}", msg);
                        match msg {
                            Msg::AddBreakpoint(bp) => {
                                let mut bp = bp.clone();
                                bp.install(pid);
                                debugger.breakpoints.push(bp);
                            }
                            Msg::RemoveBreakpoint(addr) => {
                                let bp = debugger
                                    .breakpoints
                                    .iter_mut()
                                    .find(|bp| bp.address == addr)
                                    .expect("Removed breakpoint that doesnt exist");
                                bp.uninstall(pid);
                                if let Some(bp_pos) = debugger
                                    .breakpoints
                                    .iter_mut()
                                    .position(|bp| bp.address == addr)
                                {
                                    debugger.breakpoints.remove(bp_pos);
                                }

                                while let Some(pos) = breakpoints_pending_reinstall
                                    .iter()
                                    .position(|(_, bp_addr)| *bp_addr == addr)
                                {
                                    breakpoints_pending_reinstall.remove(pos);
                                }
                            }
                            _ => unimplemented!("Got early state msg: {:?}", msg),
                        }
                    }

                    pid.ptrace_syscall();
                }
            }
        });

        return (sender, rec_from_debug);
    }
}
