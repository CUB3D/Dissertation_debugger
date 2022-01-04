//! A client for debugging a given process, handles process spawning and event handling for a given platform
#![feature(seek_stream_len)]
pub mod types;
pub mod debugger_state;
pub mod common_binary_file;
pub mod elf;

pub use types::*;
pub use debugger_state::*;
pub use elf::*;

use std::ops::Range;
use crossbeam_channel::{Receiver, Sender};

pub trait DebuggingClient {
    //TODO: should this return an instance of the client
    fn start(&mut self, binary_path: &str, args: &[&str]) -> (Sender<Msg>, Receiver<DebuggerMsg>);
}
#[cfg(target_os = "linux")]
pub use ptrace::{Breakpoint, FpRegs, Process};

#[cfg(not(target_os = "linux"))]
#[derive(Copy, Clone, Debug)]
pub struct Breakpoint {
    pub address: usize,
}
#[cfg(not(target_os = "linux"))]
impl Breakpoint {
    pub fn new(address: usize) -> Self {
        Self { address }
    }
}
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
pub struct FpRegs {
    pub ftw: libc::c_ushort,
    pub st_space: [libc::c_uint; 32],
    pub xmm_space: [libc::c_uint; 64],
}
#[cfg(not(target_os = "linux"))]
#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Process(pub i32);

use crate::types::MemoryMap;
use crate::types::UserRegs;
use crate::types::CallStack;
use crate::types::Syscall;
#[cfg(target_os = "linux")]
pub use linux_ptrace_debugging_client::LinuxPtraceDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "windows")]
pub use win::WindowsNTDebuggingClient as NativeDebuggingClient;
#[cfg(target_os = "macos")]
pub use mac::DarwinDebuggingClient as NativeDebuggingClient;

/// Messages send from the ui to the debugging client
#[derive(Clone)]
pub enum Msg {
    /// Start running an instance of the binary
    Start,
    /// Resume executing the binary
    Continue,
    /// Set wether to single step (true) or syscall step (false)
    SingleStep(bool),
    /// Register and install a breakpoint
    AddBreakpoint(Breakpoint),
    /// Remove the breakpoint at the given address
    RemoveBreakpoint(usize),
    /// Install the breakpoint that has already been added at the given address
    InstallBreakpoint {
        address: usize,
    },
    DoSingleStep,
    /// Restart the running process
    Restart,
    /// Stop the process
    Stop
}

/// Messages send from the debugging client to the ui to notify of an event
#[derive(Clone, Debug)]
pub enum DebuggerMsg {
    /// The child has hit a singlestep breakpoint, control returned to caller
    Trap,
    /// The child has hit a int3 breakpoint, control returned to caller at the start of the
    /// original instruction that was overwriten with the bp
    /// At this point the breakpoint is no longer active, it can be reinstalled with
    /// InstallBreakpoint, however this must be done after executing past this point
    /// or it will be hit in a loop.
    BPTrap { breakpoint: Breakpoint },
    /// The child has hit a syscall breakpoint, control returned to caller
    SyscallTrap,
    /// The process has spawned
    ProcessSpawn(Process),
    /// The given process has died with the given status
    ProcessDeath(Process, usize),
    /// A child process has spawned
    ChildProcessSpawn(Process),
    /// The process has stopped, we have a new call stack to display
    CallStack(Process, CallStack),
    /// The process has executed a syscall
    Syscall(Process, Syscall),
    /// The process is updating the memory map
    MemoryMap(Process, MemoryMap),
    /// The given process has received new user registers
    UserRegisters(Process, Box<UserRegs>),
    /// The given process has received new floating point registers
    FpRegisters(Process, Box<FpRegs>),
    /// The given process has new memory state
    Memory(Process, Vec<(Vec<u8>, Range<usize>)>),
}

#[cfg(target_os = "linux")]
pub mod linux_ptrace_debugging_client;


#[cfg(target_os = "windows")]
pub mod win {
    use crate::debugging_client::{DebuggingClient, FpRegs, Process};
    use crate::memory_map::{
        MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions, MemoryMapEntryPermissionsKind,
    };
    use crate::types::UserRegs;
    use crate::{DebuggerMsg, DebuggerState, Msg};
    use core::default::Default;
    use crossbeam_channel::{Receiver, Sender, unbounded};
    use std::ffi::CString;
    use windows::Win32::Foundation;
    use windows::Win32::Foundation::{HANDLE, HANDLE_FLAGS, PSTR};

    #[derive(Default)]
    pub struct WindowsNTDebuggingClient {}

    impl WindowsNTDebuggingClient {
        fn get_context(pid: u32) -> (Box<UserRegs>, Box<FpRegs>) {
            let handle = unsafe {
                ::windows::Win32::System::Threading::OpenThread(::windows::Win32::System::Threading::THREAD_GET_CONTEXT, false, pid)
            };

            let ctx = unsafe {
                let mut ctx = Box::<
                    ::windows::Win32::System::Diagnostics::Debug::CONTEXT,
                >::new_zeroed()
                    .assume_init();
                ctx.ContextFlags = 0x00010000
                    | 0x00000001
                    | 0x00000002
                    | 0x00000004
                    | 0x00000008
                    | 0x00000010
                    | 0x00000020
                    | 0x00000040;
                let r = ::windows::Win32::System::Diagnostics::Debug::GetThreadContext(handle, ctx.as_mut());
                assert_eq!(r.as_bool(), true, "Get thread context");
                println!("TC: {}, {} {} {}", r.0, ctx.Rax, ctx.Rbx, ctx.Rip);
                ctx
            };

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

            let mut fp_regs = unsafe { Box::<FpRegs>::new_zeroed().assume_init() };

            // Extract 80 bit x87 FPU registers
            for (index, reg) in unsafe { ctx.Anonymous.FltSave.FloatRegisters }.iter().enumerate() {
                fp_regs.st_space[index*4] = ((reg.High >> 32) & 0xFFFF_FFFF) as u32;
                fp_regs.st_space[index*4 + 1] = (reg.High & 0xFFFF_FFFF) as u32;
                fp_regs.st_space[index*4 + 2] = ((reg.Low >> 32) & 0xFFFF_FFFF) as u32;
                fp_regs.st_space[index*4 + 3] = (reg.Low & 0xFFFF_FFFF) as u32;
            }

            fp_regs.ftw = unsafe { ctx.Anonymous.FltSave.TagWord } as u16;

            // Extract 128 bit x/ymm regs into 32 bit chunks to match ptrace format
            for (index, reg) in unsafe { ctx.Anonymous.FltSave.XmmRegisters }.iter().enumerate() {
                fp_regs.xmm_space[index*4] = ((reg.High >> 32) & 0xFFFF_FFFF) as u32;
                fp_regs.xmm_space[index*4 + 1] = (reg.High & 0xFFFF_FFFF) as u32;
                fp_regs.xmm_space[index*4 + 2] = ((reg.Low >> 32) & 0xFFFF_FFFF) as u32;
                fp_regs.xmm_space[index*4 + 3] = (reg.Low & 0xFFFF_FFFF) as u32;
            }

            (user_regs, fp_regs)
        }
    }

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
                            let mut pi = Box::<
                                ::windows::Win32::System::Threading::PROCESS_INFORMATION,
                            >::new_zeroed()
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

                        println!("Started process id = {}", pi.dwProcessId);

                        // Check that the target is 64bit as well as us
                        // unsafe  {
                        //     let mut b = Box::<::windows::Win32::Foundation::BOOL>::new_zeroed().assume_init();
                        //     let r = ::windows::Win32::System::Threading::IsWow64Process(::windows::Win32::Foundation::HANDLE(pi.dwProcessId as isize), b.as_mut());
                        //     assert_eq!(r.as_bool(), true, "Target must be 64 bit");
                        //     assert_eq!(b.as_bool(), true, "Target must be 64 bit");
                        // }

                        unsafe {
                            let r =
                                ::windows::Win32::System::Diagnostics::Debug::DebugActiveProcess(
                                    pi.dwProcessId,
                                );
                            // assert_eq!(r.as_bool(), true, "Debugger attached");
                        }

                        let mut local_debugger_state = DebuggerState::default();

                        send_from_debug
                            .send(DebuggerMsg::ProcessSpawn(Process(pi.dwProcessId as i32)))
                            .expect("Send proc");

                        loop {
                            let evt = unsafe {
                                //TODO: use waitfordebugex
                                let mut evt = Box::<
                                    ::windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT,
                                >::new_zeroed()
                                    .assume_init();
                                evt.dwProcessId = pi.dwProcessId;
                                let r =
                                    ::windows::Win32::System::Diagnostics::Debug::WaitForDebugEvent(
                                        evt.as_mut(),
                                        0,
                                    );
                                // assert_eq!(r.as_bool(), true, "Debug event recieved");
                                evt
                            };
                            if evt.dwDebugEventCode != 0 {
                                println!("Got debug event {}", evt.dwDebugEventCode);

                                let handle = unsafe {
                                    ::windows::Win32::System::Threading::OpenProcess(::windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION | ::windows::Win32::System::Threading::THREAD_GET_CONTEXT, false, pi.dwProcessId)
                                };

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
                                        // println!("Base addr = {:X}", mbi.BaseAddress as usize);
                                        // println!("bytes read = {}", bytes_read);
                                        // println!("{}", mbi.Protect);
                                        base =
                                            (mbi.BaseAddress as usize + mbi.RegionSize) as *mut _;

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
                                            range: (mbi.BaseAddress as usize)
                                                ..(mbi.BaseAddress as usize + mbi.RegionSize),
                                            path: "".to_string(),
                                            permissions: MemoryMapEntryPermissions {
                                                read: r,
                                                write: w,
                                                execute: e,
                                                kind: MemoryMapEntryPermissionsKind::Private,
                                            },
                                        })
                                    }
                                }
                                send_from_debug.send(DebuggerMsg::MemoryMap(MemoryMap(mmap)));

                                let (user_regs, fp_regs) = WindowsNTDebuggingClient::get_context(pi.dwThreadId);
                                send_from_debug.send(DebuggerMsg::UserRegisters(Process(pi.dwProcessId as i32), user_regs));
                                send_from_debug.send(DebuggerMsg::FpRegisters(Process(pi.dwProcessId as i32), fp_regs));

                                match evt.dwDebugEventCode {
                                    ::windows::Win32::System::Diagnostics::Debug::EXCEPTION_DEBUG_EVENT => {
                                        send_from_debug.send(DebuggerMsg::Trap).expect("Failed to send from debug");
                                        println!("Exception");
                                    }
                                    ::windows::Win32::System::Diagnostics::Debug::CREATE_THREAD_DEBUG_EVENT => {
                                        let info = unsafe { evt.u.CreateThread };
                                        //TODO: this has extra info like start addr
                                        //TODO: bad cast
                                        send_from_debug.send(DebuggerMsg::ChildProcessSpawn(Process(info.hThread.0 as i32))).expect("Failed to send from debug");

                                        send_from_debug.send(DebuggerMsg::Trap).expect("Failed to send from debug");
                                        println!("CREATE_THREAD");
                                    }
                                    ::windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT => {
                                        send_from_debug.send(DebuggerMsg::Trap).expect("Failed to send from debug");
                                        println!("CREATE_PROC");
                                    }
                                    ::windows::Win32::System::Diagnostics::Debug::EXIT_THREAD_DEBUG_EVENT => {
                                        send_from_debug.send(DebuggerMsg::Trap).expect("Failed to send from debug");
                                        println!("EXIT_THREAD");
                                    }
                                    ::windows::Win32::System::Diagnostics::Debug::EXIT_PROCESS_DEBUG_EVENT => {
                                        send_from_debug.send(DebuggerMsg::Trap).expect("Failed to send from debug");
                                        println!("EXIT_PROCESS");
                                    }
                                    ::windows::Win32::System::Diagnostics::Debug::LOAD_DLL_DEBUG_EVENT => {
                                        send_from_debug.send(DebuggerMsg::Trap).expect("Failed to send from debug");
                                        println!("LOAD_DLL");
                                    }
                                    _ => {
                                        unimplemented!("Got debug event code {}", evt.dwDebugEventCode);
                                    }
                                }

                                loop {
                                    let msg = reciever.recv().expect("No continue");
                                    local_debugger_state.apply_state_transform(msg.clone());
                                    match msg {
                                        Msg::Continue => break,
                                        _ => panic!("Unexpected msg")
                                    }
                                }

                                unsafe {
                                    ::windows::Win32::System::Diagnostics::Debug::ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, ::windows::Win32::Foundation::DBG_CONTINUE.0 as _);
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

#[cfg(target_os = "macos")]
pub mod mac {
    use crate::debugging_client::{DebuggingClient, FpRegs, Process};
    use crate::memory_map::{
        MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions, MemoryMapEntryPermissionsKind,
    };
    use crate::types::UserRegs;
    use crate::{DebuggerMsg, DebuggerState, Msg};
    use core::default::Default;
    use crossbeam_channel::{Receiver, Sender, unbounded};
    use std::ffi::CString;

    #[derive(Default)]
    pub struct DarwinDebuggingClient {}

    impl DarwinDebuggingClient {
        pub fn spawn_process(name: &str) -> Process {
            let mut attr = unsafe { Box::<libc::posix_spawnattr_t>::new_zeroed().assume_init() };
            let mut pid = unsafe { Box::<libc::pid_t>::new_zeroed().assume_init() };

            unsafe {
                let status = libc::posix_spawnattr_init(attr.as_mut());
                assert_eq!(status, 0, "Unable to init spawnattr");
            }

            let posix_flags = libc::POSIX_SPAWN_START_SUSPENDED | 0x0100;
            unsafe {
                let status = libc::posix_spawnattr_setflags(attr.as_mut(), posix_flags as libc::c_short);
                assert_eq!(status, 0, "Failed to set flags");
            }

            unsafe {
                let name_cstr = CString::new(name).unwrap();
                let envp = core::ptr::null_mut();
                let status = libc::posix_spawn(pid.as_mut(), name_cstr.as_ptr(), core::ptr::null_mut(), attr.as_mut(), core::ptr::null_mut(), envp);
                assert_eq!(status, 0, "Failed to spawn");
            }

            // Attach to proc
            unsafe {
                let status = libc::ptrace(libc::PT_ATTACHEXC, *pid, core::ptr::null_mut(), 0);
                assert_ne!(status, -1, "Failed to attach");
            }


            // Get task
            let task = unsafe {
                let mut task = Box::<libc::task_t>::new_zeroed().assume_init();
                let krt = libc::task_for_pid(libc::mach_task_self(), *pid, task.as_mut());
                assert_eq!(krt, libc::KERN_SUCCESS, "task_for_pid fail");
                task
            };


            let exception_port = unsafe {
                let mut exception_port = Box::<libc::mach_port_t>::new_zeroed().assume_init();
                let krt = mach::mach_port::mach_port_allocate(libc::mach_task_self(), mach::port::MACH_PORT_RIGHT_RECEIVE, exception_port.as_mut());
                assert_eq!(krt, libc::KERN_SUCCESS, "allocate new port fail");


                let krt = mach::mach_port::mach_port_insert_right(libc::mach_task_self(), *exception_port, *exception_port, mach::message::MACH_MSG_TYPE_MAKE_SEND);
                assert_eq!(krt, libc::KERN_SUCCESS, "authorizing new port fail");

                let krt = mach::task::task_set_exception_ports(*task, mach::exception_types::EXC_MASK_ALL, *exception_port, (mach::exception_types::EXCEPTION_STATE_IDENTITY | mach::exception_types::MACH_EXCEPTION_CODES) as _, mach::thread_status::x86_THREAD_STATE64);
                assert_eq!(krt, libc::KERN_SUCCESS, "register new port fail");

                exception_port
            };

            // Resume proc
            unsafe {
                mach::task::task_resume(*task);
            }

            loop {
                unsafe {
                    let timeout = 100;
                    let mut req = Box::<mach::message::mach_msg_header_t>::new_zeroed().assume_init();
                    let krt = mach::message::mach_msg(req.as_mut(), mach::message::MACH_RCV_MSG | mach::message::MACH_RCV_TIMEOUT|mach::message::MACH_RCV_INTERRUPT, 0, core::mem::size_of_val(&req) as _, *exception_port, timeout, libc::MACH_PORT_NULL as _);
                }
            }

            return Process(0);
        }
    }

    impl DebuggingClient for DarwinDebuggingClient {
        fn start(&mut self, binary_path: &str) -> (Sender<Msg>, Receiver<DebuggerMsg>) {
            let (send_from_debug, rec_from_debug) = unbounded();
            let (sender, reciever) = unbounded();

            // Can't send a ref to a thread
            let binary_path = binary_path.to_string();
            std::thread::spawn(move || {
                let msg = reciever.recv().expect("failed to get msg");
                match msg {
                    Msg::Start => {
                        let pid = DarwinDebuggingClient::spawn_process(&binary_path);

                        send_from_debug
                            .send(DebuggerMsg::ProcessSpawn(pid))
                            .expect("Send proc");
                    }
                    _ => unimplemented!()
                }
            });


            return (sender, rec_from_debug);
        }
    }
}
