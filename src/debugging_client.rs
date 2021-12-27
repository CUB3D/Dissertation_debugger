//! A client for debugging a given process, handles process spawning and event handling for a given platform
use crossbeam_channel::{Receiver, Sender};

pub trait DebuggingClient {
    //TODO: should this return an instance of the client
    fn start(&mut self, binary_path: &str) -> (Sender<Msg>, Receiver<DebuggerMsg>);
}
#[cfg(target_os = "linux")]
use ptrace::{Breakpoint, FpRegs, Process};

#[cfg(target_os = "windows")]
#[derive(Copy, Clone, Debug)]
pub struct Breakpoint {
    pub address: usize
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
    /// The process has stopped, we have a new call stack to display
    CallStack(CallStack),
    /// The process has executed a syscall
    Syscall(String),
    /// The process is updating the memory map
    MemoryMap(MemoryMap)
}

#[cfg(target_os = "linux")]
pub mod linux {
    use crate::debugging_client::DebuggingClient;
    use crate::debugging_client::{DebuggerMsg, Msg};
    use crate::stack::{CallStack, StackFrame};
    use crossbeam_channel::{unbounded, Receiver, Sender};

    use ptrace::Ptrace;

    use std::iter::Iterator;

    use unwind::{Accessors, AddressSpace, Byteorder, Cursor as StackCursor, PTraceState, RegNum};
    use crate::DebuggerState;

    #[derive(Default)]
    pub struct LinuxPtraceDebuggingClient {}

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
                            .send(DebuggerMsg::ProcessSpwn(child))
                            .expect("Send proc");

                        child.ptrace_singlestep();

                        let mut is_singlestep = false;
                        let mut in_syscall = false;

                        loop {
                            let status = child.wait_for();

                            if status.wifstopped() {
                                // Walk the call stack
                                let mut call_stack = Vec::new();

                                let state = PTraceState::new(child.0 as u32).unwrap();
                                let space =
                                    AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT)
                                        .unwrap();
                                let mut cursor = StackCursor::remote(&space, &state).unwrap();
                                loop {
                                    let ip = cursor.register(RegNum::IP).unwrap();

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

                                    if !cursor.step().unwrap() {
                                        break;
                                    }
                                }
                                send_from_debug.send(DebuggerMsg::CallStack(CallStack(call_stack)));

                                if let Some(mmap) = ptrace::get_memory_map(child.0) {
                                    send_from_debug.send(DebuggerMsg::MemoryMap(mmap));
                                }

                                // Handle the various trap types
                                let stopsig = status.wstopsig();
                                if stopsig == (libc::SIGTRAP | 0x80) {
                                    if !in_syscall {
                                        // Figure out the details of the syscall
                                        let user_regs = child.ptrace_getregs();
                                        let syscall_desc = match user_regs.orig_ax as libc::c_long {
                                            libc::SYS_brk => format!("brk({})", user_regs.di),
                                            libc::SYS_arch_prctl => {
                                                format!("SYS_arch_prctl({})", user_regs.di)
                                            }
                                            libc::SYS_mmap => format!("SYS_mmap(?)"),
                                            libc::SYS_access => format!("SYS_access(?)"),
                                            libc::SYS_newfstatat => format!("SYS_newfstatat(?)"),
                                            libc::SYS_mprotect => format!("SYS_mprotect(?)"),
                                            libc::SYS_write => format!("SYS_write(?)"),
                                            libc::SYS_read => format!("SYS_read(?)"),
                                            libc::SYS_munmap => format!("SYS_munmap(?)"),
                                            libc::SYS_exit_group => format!("SYS_exit_group(?)"),
                                            libc::SYS_pread64 => format!("SYS_pread64(?)"),
                                            libc::SYS_close => {
                                                format!("close({})", user_regs.di)
                                            }
                                            libc::SYS_openat => {
                                                let fd_name = match user_regs.di as i32 {
                                                    -100 => "AT_FDCWD".to_string(),
                                                    _ => format!("{}", user_regs.di),
                                                };

                                                let str_arg = unsafe {
                                                    ptrace::ptrace_read_string(
                                                        child.0,
                                                        user_regs.si as i64,
                                                    )
                                                };

                                                format!("openat({}, {}, ?)", fd_name, str_arg)
                                            }
                                            _ => format!("Unknown({})", user_regs.orig_ax),
                                        };
                                        send_from_debug.send(DebuggerMsg::Syscall(syscall_desc));

                                        send_from_debug
                                            .send(DebuggerMsg::SyscallTrap {
                                                user_regs: user_regs.clone(),
                                                fp_regs: child.ptrace_getfpregs(),
                                            })
                                            .expect("Failed to send from debug");
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
                                        if child.ptrace_peektext(regs.ip as usize - 1) & 0xFF
                                            == 0xCC
                                        {
                                            println!(
                                                "Hit a breakpoint @ 0x{:x} ::: {:X}",
                                                regs.ip,
                                                child.ptrace_peektext(regs.ip as usize - 1)
                                            );
                                            let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == regs.ip as usize - 1).expect("Hit a breakpoint, but we can't find it to uninstall");
                                            bp.uninstall(child);
                                            // Go back to the start of the original instruction so it actually gets executed
                                            unsafe {
                                                libc::ptrace(
                                                    libc::PTRACE_POKEUSER,
                                                    child,
                                                    8 * libc::RIP,
                                                    regs.ip - 1,
                                                )
                                            };
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
                                        child.ptrace_singlestep();
                                        child.wait_for();
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
                                .send(DebuggerMsg::ProcessSpwn(Process(pi.dwProcessId as i32)))
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
