use crate::{DebuggingClient, FpRegs, Process};
use crate::types::{
    MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions, MemoryMapEntryPermissionsKind,
};
use crate::types::UserRegs;
use crate::{DebuggerMsg, DebuggerState, Msg};
use core::default::Default;
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::ffi::CString;
use libc::mach_msg_type_number_t;
use mach::mach_types::{task_t, thread_act_port_array_t};
use mach::structs::x86_thread_state64_t;
use mach::task::{task_suspend, task_threads};
use mach::thread_act::thread_get_state;
use mach::thread_status::{thread_state_t, x86_THREAD_STATE32, x86_THREAD_STATE64};
use mach::vm::{mach_vm_machine_attribute, mach_vm_protect, mach_vm_read, mach_vm_write};
use mach::vm_attributes::{MATTR_CACHE, MATTR_VAL_CACHE_FLUSH};
use mach::vm_prot::VM_PROT_COPY;

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
        println!("Spawn proc pid = {}", *pid);

        // Attach to proc
        // unsafe {
        //     let status = libc::ptrace(libc::PT_ATTACHEXC, *pid, core::ptr::null_mut(), 0);
        //     assert_ne!(status, -1, "Failed to attach");
        // }

        unsafe {
            let status = libc::ptrace(libc::PT_ATTACH, *pid, core::ptr::null_mut(), 0);
            assert_ne!(status, -1, "Failed to attach");
        }



        // Get task for pid
        let task = unsafe {
            let mut task = Box::<libc::task_t>::new_zeroed().assume_init();
            let krt = libc::task_for_pid(libc::mach_task_self(), *pid, task.as_mut());
            assert_eq!(krt, libc::KERN_SUCCESS, "task_for_pid fail");
            task
        };

        // Get threads in proc
        let mut thread_list = unsafe { Box::<thread_act_port_array_t>::new_zeroed().assume_init()};
        let mut thread_count = unsafe { Box::<mach_msg_type_number_t>::new_zeroed().assume_init()};
        let res = unsafe { task_threads(*task, thread_list.as_mut(), thread_count.as_mut())};
        assert_eq!(res, libc::KERN_SUCCESS);
        assert_eq!(*thread_count, 1);
        println!("Threads = {}", thread_count);

        let tid = unsafe { **thread_list};
        println!("Tid = {}", tid);

        //TODO: need to make this work properly, the enum in thread_get_state and the type here need to match,
        // need to create entries for arm64 and update the calculation below as well
        let mut thread_state = x86_thread_state64_t::new();
        // x86_THREAD_STATE64_COUNT
        let mut sc = (std::mem::size_of::<x86_thread_state64_t>() / std::mem::size_of::<libc::c_int>()) as u32;
        println!("sc={}", sc);
        sc = 1000;
        let res = unsafe { thread_get_state(tid, x86_THREAD_STATE32, (&mut thread_state) as *mut _ as thread_state_t, &mut sc as *mut _)};
        println!("res = {:X}", res);
        assert_eq!(res, libc::KERN_SUCCESS);
        println!("RIP = {}", thread_state.__rip);


        // let addr = 0x100003e20;
        // let mut buf = [0usize; 1];
        // let mut out_size: mach_msg_type_number_t = 0;
        // let res = unsafe { mach_vm_read(*task, addr, 1, &mut buf as *mut usize, &mut out_size as *mut _) };
        // assert_eq!(res, libc::KERN_SUCCESS);
        // println!("Got out_size = {}", out_size);
        // let original_byte = buf[0] & 0xFF;
        // let new_byte = buf[0] | 0xCC;
        // println!("Got new_byte = {:X}", new_byte);
        // buf[0] = new_byte;
        // // let res = unsafe { mach_vm_write(*task, addr, &buf as *const _ as usize, out_size) };
        // // assert_eq!(res, libc::KERN_SUCCESS);

        unsafe { libc::ptrace(libc::PT_STEP, *pid, 0 as *mut _, 0) };

        loop {
            // Wait for proc
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status as *mut _, 0)};
            // println!("pid = {}, status = {}", pid, status);

            if libc::WIFSTOPPED(status) {
                let stat = libc::WSTOPSIG(status);
                if stat == libc::SIGTRAP {
                    println!("TRAP");
                } else {
                    println!("Not trap");
                }
            } else {
                // println!("Not stopped");
            }

            // Get task for pid
            let task = unsafe {
                let mut task = task_t::default();
                let krt = libc::task_for_pid(libc::mach_task_self(), pid, &mut task as *mut _);
                assert_eq!(krt, libc::KERN_SUCCESS, "task_for_pid fail");
                task
            };

            // // Get threads in proc
            let mut thread_list = unsafe { Box::<thread_act_port_array_t>::new_zeroed().assume_init()};
            let mut thread_count = unsafe { Box::<mach_msg_type_number_t>::new_zeroed().assume_init()};
            let res = unsafe { task_threads(task, thread_list.as_mut(), thread_count.as_mut())};
            assert_eq!(res, libc::KERN_SUCCESS);
            assert_eq!(*thread_count, 1);
            // println!("Threads = {}", thread_count);

            //TODO: need to make this work properly, the enum in thread_get_state and the type here need to match,
            // need to create entries for arm64 and update the calculation below as well
            let mut thread_state = x86_thread_state64_t::new();
            // x86_THREAD_STATE64_COUNT
            let mut sc = (std::mem::size_of::<x86_thread_state64_t>() / std::mem::size_of::<libc::c_int>()) as u32;
            // println!("sc={}", sc);
            sc = 1000;
            let res = unsafe { thread_get_state(tid, x86_THREAD_STATE32, (&mut thread_state) as *mut _ as thread_state_t, &mut sc as *mut _)};
            // println!("res = {:X}", res);
            assert_eq!(res, libc::KERN_SUCCESS);
            // println!("RIP = {:X}", thread_state.__rip);

            if true {
                let addr = 0x100003e20;
                // Make memory r/w first
                let prot = libc::VM_PROT_READ | libc::VM_PROT_WRITE;
                let res = unsafe { mach_vm_protect(task, addr, 32, 0, prot) };
                if res != libc::KERN_SUCCESS {
                    let res = unsafe { mach_vm_protect(task, addr, 32, 0, prot | VM_PROT_COPY) };
                    assert_eq!(res, libc::KERN_SUCCESS);
                }


                let mut buf = [0usize; 1];
                let mut out_size: mach_msg_type_number_t = 0;
                let res = unsafe { mach_vm_read(task, addr, 1, &mut buf as *mut usize, &mut out_size as *mut _) };
                assert_eq!(res, libc::KERN_SUCCESS);
                // println!("Got out_size = {}", out_size);
                let original_byte = buf[0] & 0xFF;
                println!("Obyte = {:X}", buf[0]);
                let new_byte = buf[0] | 0xCC;
                // println!("Got new_byte = {:X}", new_byte);
                buf[0] = new_byte;
                let res = unsafe { mach_vm_write(task, addr, &buf as *const _ as usize, 1) };
                assert_eq!(res, libc::KERN_SUCCESS);

                // Make memory r/x after
                let prot = libc::VM_PROT_READ | libc::VM_PROT_EXECUTE;
                let res = unsafe { mach_vm_protect(task, addr, 32, 0, prot) };
                assert_eq!(res, libc::KERN_SUCCESS);

                let mut mattr = MATTR_VAL_CACHE_FLUSH;
                let res = unsafe { mach_vm_machine_attribute(task, addr, 32, MATTR_CACHE, &mut mattr as *mut _) };
                assert_eq!(res, libc::KERN_SUCCESS);
            }

            // unsafe { task_suspend(*task)};

            // let addr = 0;
            // let mut buf = [0usize; 1];
            // let buf_size = (std::mem::size_of::<u64>() / std::mem::size_of::<libc::c_int>()) as u32;
            // let mut out_size = 0;
            // unsafe { mach_vm_read(task, addr, 1, &mut buf as *mut usize, &mut out_size as *mut _) };
            // let original_byte = buf[0] & 0xFF;
            // let new_byte = buf[0] | 0xCC;
            // buf[0] = new_byte;
            // unsafe {
            //     mach_vm_write(task, addr, &buf as *const _ as usize, out_size);
            // }

            //TODO: we can probably install breakpoint here, then we can PT_Continue until we hit it


            // println!("Proc stopped, continuing");
            // let r = unsafe { libc::ptrace(libc::PT_STEP, pid, 1 as _, 0) };
            let r = unsafe { libc::ptrace(libc::PT_CONTINUE, pid, 1 as _, 0) };

            //
        // let exception_port = unsafe {
        //     let mut exception_port = Box::<libc::mach_port_t>::new_zeroed().assume_init();
        //     let krt = mach::mach_port::mach_port_allocate(libc::mach_task_self(), mach::port::MACH_PORT_RIGHT_RECEIVE, exception_port.as_mut());
        //     assert_eq!(krt, libc::KERN_SUCCESS, "allocate new port fail");
        //
        //
        //     let krt = mach::mach_port::mach_port_insert_right(libc::mach_task_self(), *exception_port, *exception_port, mach::message::MACH_MSG_TYPE_MAKE_SEND);
        //     assert_eq!(krt, libc::KERN_SUCCESS, "authorizing new port fail");
        //
        //     let krt = mach::task::task_set_exception_ports(*task, mach::exception_types::EXC_MASK_ALL, *exception_port, (mach::exception_types::EXCEPTION_STATE_IDENTITY | mach::exception_types::MACH_EXCEPTION_CODES) as _, mach::thread_status::x86_THREAD_STATE64);
        //     assert_eq!(krt, libc::KERN_SUCCESS, "register new port fail");
        //
        //     exception_port
        // };
        //
        // // Resume proc
        // unsafe {
        //     mach::task::task_resume(*task);
        // }
        //
        // loop {
        //     let exception = unsafe {
        //         let timeout = 100;
        //         let mut req = Box::<mach::message::mach_msg_header_t>::new_zeroed().assume_init();
        //         let krt = mach::message::mach_msg(req.as_mut(), mach::message::MACH_RCV_MSG | mach::message::MACH_RCV_TIMEOUT|mach::message::MACH_RCV_INTERRUPT, 0, core::mem::size_of_val(&req) as _, *exception_port, timeout, libc::MACH_PORT_NULL as _);
        //         krt
        //     };
        //     if exception == mach::message::MACH_RCV_INTERRUPT {
        //         continue;
        //     }
        //     assert_eq!(exception, mach::message::MACH_MSG_SUCCESS);
        //     unsafe { task_suspend(*task) };
        //
        //     unsafe {
        //         let mut req_buffer = Box::<mach::message::mach_msg_header_t>::new_zeroed().assume_init();
        //         let mut reply_buffer = Box::<mach::message::mach_msg_header_t>::new_zeroed().assume_init();
        //
        //         let message_parsed_correctly = mach::mach_init::mach_exc_server(req_buffer.as_mut(), reply_buffer.as_mut());
        //         if message_parsed_correctly == 0 {
        //             panic!("Failed to parse msg");
        //         }
        //     }
        }

        return Process(0);
    }
}

impl DebuggingClient for DarwinDebuggingClient {
    fn start(&mut self, binary_path: &str, arg: &[&str]) -> (Sender<Msg>, Receiver<DebuggerMsg>) {
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
