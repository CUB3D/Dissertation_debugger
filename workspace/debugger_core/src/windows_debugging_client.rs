use crate::{DebuggingClient, FpRegs, Process};
use crate::types::{
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
    fn start(&mut self, binary_path: &str, args: &[&str]) -> (Sender<Msg>, Receiver<DebuggerMsg>) {
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
                            send_from_debug.send(DebuggerMsg::MemoryMap(Process(pi.dwProcessId as i32), MemoryMap(mmap)));

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
