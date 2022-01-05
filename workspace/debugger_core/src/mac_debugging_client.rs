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
