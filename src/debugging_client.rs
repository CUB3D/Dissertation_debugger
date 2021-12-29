//! A client for debugging a given process, handles process spawning and event handling for a given platform
use crossbeam_channel::{Receiver, Sender};

pub trait DebuggingClient {
    //TODO: should this return an instance of the client
    fn start(&mut self, binary_path: &str) -> (Sender<Msg>, Receiver<DebuggerMsg>);
}
#[cfg(target_os = "linux")]
pub use ptrace::{Breakpoint, FpRegs, Process};

#[cfg(target_os = "windows")]
#[derive(Copy, Clone, Debug)]
pub struct Breakpoint {
    pub address: usize
}
#[cfg(target_os = "windows")]
impl Breakpoint{
    pub fn new(address: usize) -> Self {
        Self {
            address,
        }
    }
}
#[cfg(target_os = "windows")]
#[derive(Clone, Debug)]
pub struct FpRegs;
#[cfg(target_os = "windows")]
#[derive(Copy, Clone, Debug)]
pub struct Process(pub i32);

use crate::stack::CallStack;
#[cfg(target_os = "linux")]
pub use linux::LinuxPtraceDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "windows")]
pub use win::WindowsNTDebuggingClient as NativeDebuggingClient;
use crate::memory_map::MemoryMap;
use crate::registers::UserRegs;
use crate::syscall::Syscall;

#[derive(Clone)]
pub enum Msg {
    Start,
    Continue,
    SingleStep(bool),
    AddBreakpoint(Breakpoint),
    /// Remove the breakpoint at the given address
    RemoveBreakpoint(usize),
    /// Install the breakpoint that has already been added at the given address
    InstallBreakpoint {
        address: usize,
    },
    DoSingleStep,
}

#[derive(Clone, Debug)]
pub enum DebuggerMsg {
    /// The child has hit a singlestep breakpoint, control returned to caller
    Trap,
    /// The child has hit a int3 breakpoint, control returned to caller
    BPTrap {
        breakpoint: Breakpoint,
    },
    /// The child has hit a syscall breakpoint, control returned to caller
    SyscallTrap,
    /// The process has spawned
    ProcessSpawn(Process),
    /// A child process has spawned
    ChildProcessSpawn(Process),
    /// The process has stopped, we have a new call stack to display
    CallStack(CallStack),
    /// The process has executed a syscall
    Syscall(Syscall),
    /// The process is updating the memory map
    MemoryMap( MemoryMap),
    /// The given process has received new user registers
    UserRegisters(Process, Box<UserRegs>),
    /// The given process has received new floating point registers
    FpRegisters(Process, Box<FpRegs>)
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::collections::HashMap;
    use std::error::Error;
    use crate::debugging_client::DebuggingClient;
    use crate::debugging_client::{DebuggerMsg, Msg};
    use crate::stack::{CallStack, StackFrame};
    use crossbeam_channel::{unbounded, Receiver, Sender};

    use ptrace::{MemoryMapEntryPermissionsKind, Process, Ptrace, UserRegs};

    use std::iter::Iterator;
    use libc::user;

    use unwind::{Accessors, AddressSpace, Byteorder, Cursor as StackCursor, PTraceState, RegNum};
    use crate::DebuggerState;
    use crate::memory_map::{MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions};
    use crate::syscall::{Syscall, SyscallArg};

    #[derive(Default)]
    pub struct LinuxPtraceDebuggingClient {}

    impl LinuxPtraceDebuggingClient {
        //TODO: idea: make this struct repr(c) then we can cast easily
        fn convert_ptrace_registers(oregs: &Box<ptrace::UserRegs>) -> Box<crate::registers::UserRegs> {
            let mut regs = Box::<crate::registers::UserRegs>::default();
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

        fn get_memory_map(pid: Process) -> Option<MemoryMap> {
            if let Some(mmap) = ptrace::get_memory_map(pid.0) {
                let mmap = MemoryMap(mmap.0.iter().map(|mp| MemoryMapEntry {
                    path: mp.path.clone(),
                    range: mp.range.clone(),
                    permissions: MemoryMapEntryPermissions {
                        read: mp.permissions.read,
                        write: mp.permissions.write,
                        execute: mp.permissions.execute,
                        kind: match mp.permissions.kind {
                            ptrace::MemoryMapEntryPermissionsKind::Private => crate::memory_map::MemoryMapEntryPermissionsKind::Private,
                            ptrace::MemoryMapEntryPermissionsKind::Shared =>  crate::memory_map::MemoryMapEntryPermissionsKind::Shared,
                        }
                    }
                }).collect());

                return Some(mmap);
            }
            None
        }

        fn get_call_stack(pid: Process) -> Result<CallStack, Box<dyn Error>> {
            let mut call_stack = Vec::new();

            let state = PTraceState::new(pid.0 as u32)?;
            let space = AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT)?;
            let mut cursor = StackCursor::remote(&space, &state)?;
            loop {
                let ip = cursor.register(RegNum::IP)?;

                match (cursor.procedure_info(), cursor.procedure_name()) {
                    (Ok(ref info), Ok(ref name))
                    if ip == info.start_ip() + name.offset() =>
                        {
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
                    break
                }
            }

            Ok(CallStack(call_stack))
        }

        fn get_syscall_description(pid: Process, user_regs: &Box<ptrace::UserRegs>) -> Syscall {
            macro_rules! syscall {
                ($name: expr) => {
                        return Syscall {
                            name: $name.to_string(),
                            args: vec![]
                        };
                };

                ($name: expr, $($x:ident),+) => {
                        return Syscall {
                            name: $name.to_string(),
                            args: syscall!(@arg, $($x),+ )
                        };
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
                // libc::SYS_clone => syscall!("clone", addr, addr, u64, addr, addr, addr, addr),

                libc::SYS_openat => {
                    let fd_name = match user_regs.di as i32 {
                        -100 => "AT_FDCWD".to_string(),
                        _ => format!("{}", user_regs.di),
                    };
                    let path = unsafe { pid.read_string(user_regs.si as i64) };

                    return Syscall {
                        name: "openat".to_string(),
                        args: vec![SyscallArg::String(fd_name), SyscallArg::FilePath(path), SyscallArg::U64(user_regs.dx)]
                    };
                }
                _ => {}
            }

           let name = match user_regs.orig_ax as libc::c_long {
                libc::SYS_pread64 => format!("SYS_pread64(?)"),
                _ => format!("Unknown({})", user_regs.orig_ax),
            };

            return Syscall {
                name,
                args: vec![],
            }
        }
    }

    impl DebuggingClient for LinuxPtraceDebuggingClient {
        fn start(&mut self, binary_path: &str) -> (Sender<Msg>, Receiver<DebuggerMsg>) {
            let (send_from_debug, rec_from_debug) = unbounded();
            let (sender, reciever) = unbounded();

            // Can't send a ref to a thread
            let binary_path = binary_path.to_string();
            std::thread::spawn(move || {
                let debugger = Ptrace::new(&binary_path, "Debuggee", "")
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

                        loop {
                            let (pid, status) = Process::wait_any();

                            if status.wifstopped() {
                                if let Ok(call_stack) = LinuxPtraceDebuggingClient::get_call_stack(pid) {
                                    send_from_debug.send(DebuggerMsg::CallStack(call_stack));
                                }

                                if let Some(mmap) = LinuxPtraceDebuggingClient::get_memory_map(pid) {
                                    send_from_debug.send(DebuggerMsg::MemoryMap(mmap));
                                }

                                let user_regs = pid.ptrace_getregs();
                                let fp_regs = pid.ptrace_getfpregs();

                                let user_regs_ui = LinuxPtraceDebuggingClient::convert_ptrace_registers(&user_regs);
                                send_from_debug.send(DebuggerMsg::UserRegisters(pid, user_regs_ui.clone()));
                                send_from_debug.send(DebuggerMsg::FpRegisters(pid, fp_regs.clone()));


                                // Handle the various trap types
                                let stopsig = status.wstopsig();
                                if stopsig == (libc::SIGTRAP | 0x80) {
                                    //TODO: do we need to track this for each process?
                                    if !in_syscall.get(&pid).unwrap_or(&false) {
                                        // Figure out the details of the syscall
                                        let syscall_desc = LinuxPtraceDebuggingClient::get_syscall_description(pid, &user_regs);
                                        send_from_debug.send(DebuggerMsg::Syscall(syscall_desc));
                                        send_from_debug.send(DebuggerMsg::SyscallTrap).expect("Failed to send from debug");
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

                                    let mut regs = pid.ptrace_getregs();

                                    if event == 0 {
                                        // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                                        if pid.ptrace_peektext(regs.ip as usize - 1) & 0xFF
                                            == 0xCC
                                        {
                                            println!(
                                                "Hit a breakpoint @ 0x{:x} ::: {:X}",
                                                regs.ip,
                                                pid.ptrace_peektext(regs.ip as usize - 1)
                                            );
                                            let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == regs.ip as usize - 1).expect("Hit a breakpoint, but we can't find it to uninstall");
                                            bp.uninstall(pid);
                                            // Go back to the start of the original instruction so it actually gets executed
                                            unsafe {
                                                libc::ptrace(
                                                    libc::PTRACE_POKEUSER,
                                                    pid,
                                                    8 * libc::RIP,
                                                    regs.ip - 1,
                                                )
                                            };
                                            regs.ip -= 1;

                                            send_from_debug
                                                .send(DebuggerMsg::BPTrap {
                                                    breakpoint: *bp,
                                                })
                                                .expect("Faeild to send from debug");
                                        } else {
                                            send_from_debug
                                                .send(DebuggerMsg::Trap).expect("Faeild to send from debug");
                                        }
                                    } else {
                                        match event {
                                            libc::PTRACE_EVENT_FORK => {
                                                let pid = pid.ptrace_geteventmsg();
                                                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACESYSGOOD)};
                                                // self.processes.insert(pid as i32, ());
                                                println!("Child forked {}", pid);
                                                Process(pid as i32).ptrace_syscall();
                                            }
                                            libc::PTRACE_EVENT_VFORK => {
                                                let pid = pid.ptrace_geteventmsg();
                                                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACESYSGOOD)};
                                                // self.processes.insert(pid as i32, ());
                                                println!("Child vforked {}", pid);
                                                Process(pid as i32).ptrace_syscall();
                                            }
                                            libc::PTRACE_EVENT_CLONE => {
                                                let pid = pid.ptrace_geteventmsg();
                                                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACESYSGOOD)};
                                                send_from_debug.send(DebuggerMsg::ChildProcessSpawn(Process(pid as i32)));
                                                println!("Child cloned {}", pid);
                                            }
                                            libc::PTRACE_EVENT_EXIT => {
                                                let exit_status = pid.ptrace_geteventmsg();
                                                println!("child {:?} exit with status {}", pid, exit_status);
                                                // self.processes.remove(&pid.0);
                                                // std::process::exit(0);
                                            }
                                            _ => panic!("Unknown ptrace event: {}", event)
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
                                        println!("Installed bp at {:?}, success: {}", bp, success);
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
                                    _ => panic!("unexpected msg"),
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
}

#[cfg(target_os = "windows")]
pub mod win {
    use crate::debugging_client::{DebuggingClient, FpRegs, Process};
    use core::default::Default;
    use std::ffi::CString;
    use crossbeam_channel::{Receiver, Sender, unbounded};
    use windows::Win32::Foundation;
    use windows::Win32::Foundation::{HANDLE, HANDLE_FLAGS, PSTR};
    use crate::{DebuggerMsg, Msg};
    use crate::memory_map::{MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions, MemoryMapEntryPermissionsKind};
    use crate::registers::UserRegs;

    #[derive(Default)]
    pub struct WindowsNTDebuggingClient {}

    impl DebuggingClient for WindowsNTDebuggingClient {
        fn start(&mut self, binary_path: &str) -> (Sender<Msg>, Receiver<DebuggerMsg>) {
            let (send_from_debug, rec_from_debug) = unbounded();
            let (sender, reciever) = unbounded();

            // Can't send a ref to a thread
            let binary_path = binary_path.to_string();
            std::thread::spawn(move || {
                let binary_path = CString::new(binary_path).unwrap();
                let mut bpath_bytevec = binary_path.as_bytes().to_vec();

                let msg = reciever.recv().expect("failed to get msg");
                match msg {
                    Msg::Start => {
                        let pi = unsafe {
                            let mut si = Box::<::windows::Win32::System::Threading::STARTUPINFOA>::new_zeroed()
                                .assume_init();
                            let mut pi =
                                Box::<::windows::Win32::System::Threading::PROCESS_INFORMATION>::new_zeroed()
                                    .assume_init();
                            let r = ::windows::Win32::System::Threading::CreateProcessA(
                                PSTR::default(),
                                PSTR(bpath_bytevec.as_mut_ptr()),
                                core::ptr::null_mut(),
                                core::ptr::null_mut(),
                                false,
                                ::windows::Win32::System::Threading::DEBUG_PROCESS,
                                core::ptr::null_mut(),
                                PSTR::default(),
                                si.as_mut(),
                                pi.as_mut(),
                            );
                            assert_eq!(r.as_bool(), true, "Process started successfully");
                            pi
                        };

                        // Check that the target is 64bit as well as us
                        // unsafe  {
                        //     let mut b = Box::<::windows::Win32::Foundation::BOOL>::new_zeroed().assume_init();
                        //     let r = ::windows::Win32::System::Threading::IsWow64Process(::windows::Win32::Foundation::HANDLE(pi.dwProcessId as isize), b.as_mut());
                        //     assert_eq!(r.as_bool(), true, "Target must be 64 bit");
                        //     assert_eq!(b.as_bool(), true, "Target must be 64 bit");
                        // }

                        unsafe {
                            let r = ::windows::Win32::System::Diagnostics::Debug::DebugActiveProcess(pi.dwProcessId);
                            // assert_eq!(r.as_bool(), true, "Debugger attached");
                        }

                        send_from_debug
                                .send(DebuggerMsg::ProcessSpawn(Process(pi.dwProcessId as i32)))
                                .expect("Send proc");

                            loop {
                                let evt = unsafe {
                                    //TODO: use waitfordebugex
                                    let mut evt = Box::<::windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT>::new_zeroed().assume_init();
                                    evt.dwProcessId = pi.dwProcessId;
                                    let r = ::windows::Win32::System::Diagnostics::Debug::WaitForDebugEvent(evt.as_mut(), 0);
                                    // assert_eq!(r.as_bool(), true, "Debug event recieved");
                                    evt
                                };
                                if evt.dwDebugEventCode != 0 {
                                    println!("Got debug event {}", evt.dwDebugEventCode);

                                    let handle = unsafe { ::windows::Win32::System::Threading::OpenProcess(::windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION | ::windows::Win32::System::Threading::THREAD_GET_CONTEXT, false, pi.dwProcessId) };

                                    // Read memory map
                                    let mut mmap = Vec::new();
                                    unsafe {
                                        let mut base = core::ptr::null_mut();
                                        loop {
                                            let mut mbi = Box::<::windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION>::new_zeroed().assume_init();
                                            let bytes_read = ::windows::Win32::System::Memory::VirtualQueryEx(handle, base, mbi.as_mut(), core::mem::size_of::<::windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION>());
                                            if bytes_read == 0 {
                                                break;
                                            }
                                            println!("Base addr = {:X}", mbi.BaseAddress as usize);
                                            println!("bytes read = {}", bytes_read);
                                            println!("{}", mbi.Protect);
                                            base = (mbi.BaseAddress as usize + mbi.RegionSize) as *mut _;

                                            let (r, w, e) = match mbi.Protect {
                                                ::windows::Win32::System::Memory::PAGE_EXECUTE => (false, false, true),
                                                ::windows::Win32::System::Memory::PAGE_EXECUTE_READ => (true, false, true),
                                                ::windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE => (true, true, true),
                                                ::windows::Win32::System::Memory::PAGE_EXECUTE_WRITECOPY => (true, true, true),
                                                ::windows::Win32::System::Memory::PAGE_NOACCESS => (false, false, false),
                                                ::windows::Win32::System::Memory::PAGE_READONLY => (true, false, false),
                                                ::windows::Win32::System::Memory::PAGE_READWRITE => (true, true, false),
                                                ::windows::Win32::System::Memory::PAGE_WRITECOPY => (true, true, false),
                                                //TODO: double check this and page_guard settings
                                                ::windows::Win32::System::Memory::PAGE_TARGETS_INVALID => (true, true, false),
                                                ::windows::Win32::System::Memory::PAGE_TARGETS_NO_UPDATE => (true, true, false),
                                                _ => {
                                                    println!("Unsupported page perms: {:X}, assuming ---", mbi.Protect);
                                                    (false, false, false)
                                                }
                                            };

                                            mmap.push(MemoryMapEntry {
                                                range: (mbi.BaseAddress as usize)..(mbi.BaseAddress as usize + mbi.RegionSize),
                                                path: "".to_string(),
                                                permissions: MemoryMapEntryPermissions {
                                                    read: r,
                                                    write: w,
                                                    execute: e,
                                                    kind: MemoryMapEntryPermissionsKind::Private,
                                                }
                                            })
                                        }
                                    }
                                    send_from_debug.send(DebuggerMsg::MemoryMap(MemoryMap(mmap)));


                                    //TODO: sending register state should be its own event, not connected to traps, as windows has uses events, rather than traps, so not all debuggee pauses are due to a bp/syscall_trap
                                    unsafe {
                                        //TODO: not working
                                        let mut ctx = Box::<::windows::Win32::System::Diagnostics::Debug::CONTEXT>::new_zeroed().assume_init();
                                        ctx.ContextFlags = 0x00010000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040;
                                        let r = ::windows::Win32::System::Diagnostics::Debug::GetThreadContext(handle, ctx.as_mut());
                                        // assert_eq!(r.as_bool(), true, "Get thread context");

                                        let mut user_regs = Box::new(UserRegs::default());
                                        user_regs.ax = ctx.Rax;
                                        user_regs.bx = ctx.Rbx;
                                        user_regs.cx = ctx.Rcx;
                                        user_regs.dx = ctx.Rdx;

                                        user_regs.bp = ctx.Rbp;
                                        user_regs.sp = ctx.Rsp;
                                        user_regs.si = ctx.Rsi;
                                        user_regs.di = ctx.Rdi;

                                        user_regs.r8 = ctx.R8;
                                        user_regs.r9 = ctx.R9;
                                        user_regs.r10 = ctx.R10;
                                        user_regs.r11 = ctx.R11;
                                        user_regs.r12 = ctx.R12;
                                        user_regs.r13 = ctx.R13;
                                        user_regs.r14 = ctx.R14;
                                        user_regs.r15 = ctx.R15;

                                        user_regs.ip = ctx.Rip;

                                        user_regs.flags = ctx.EFlags as u64;

                                        user_regs.gs = ctx.SegGs as u64;
                                        user_regs.fs = ctx.SegFs as u64;
                                        user_regs.ds = ctx.SegDs as u64;
                                        user_regs.cs = ctx.SegCs as u64;
                                        user_regs.ss = ctx.SegSs as u64;

                                        send_from_debug.send(DebuggerMsg::Trap { user_regs, fp_regs: Box::new(FpRegs {}) });
                                    }


                                    match evt.dwDebugEventCode {
                                        ::windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT => {
                                            let status = ::windows::Win32::Foundation::DBG_CONTINUE;
                                            unsafe {
                                                ::windows::Win32::System::Diagnostics::Debug::ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, status.0 as _);
                                            }
                                        }
                                        _ => {}
                                    }



                                }
                            }
                    }
                    _ => {}
                }
                drop(binary_path);
            });

            return (sender, rec_from_debug);
        }
    }
}
