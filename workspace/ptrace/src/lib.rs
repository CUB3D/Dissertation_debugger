#![feature(new_uninit)]

#[cfg(target_os = "linux")]
pub use linux_ptrace::*;
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(all(target_os = "linux", feature="breakpoints"))]
pub mod breakpoint;
#[cfg(target_os = "linux")]
pub mod types;
pub mod event_debugger;

#[cfg(target_os = "linux")]
pub use process::*;
#[cfg(target_os = "linux")]
pub use types::*;
#[cfg(all(target_os = "linux", feature="breakpoints"))]
pub use breakpoint::*;
#[cfg(target_os = "linux")]
pub use linux_memory_map::*;

#[cfg(target_os = "linux")]
mod linux_ptrace {
    use crate::process::Process;
    use std::ffi::CString;
    use std::error::Error;

    /// Read a null-terminated (cstring) from the process `child` at address `addr`,
    /// # Safety
    /// Unsafe as the given pointer is not checked for either alignment or the existance of a valid null-terminated string
    pub unsafe fn ptrace_read_string(child: i32, addr: i64) -> String {
        let mut str_arg = String::new();
        let mut ptr = addr;
        'outer: loop {
            let data = libc::ptrace(libc::PTRACE_PEEKDATA, child, ptr, 0);
            let data = data.to_ne_bytes();

            for elem in data {
                if let Some(c) = char::from_u32(elem as u32) {
                    if c == '\0' {
                        break 'outer;
                    }
                    str_arg.push(c);
                } else {
                    break 'outer;
                }
            }
            ptr += 8;
        }
        str_arg
    }

    type PTraceResult<T> = Result<T, Box<dyn Error>>;

    pub struct Ptrace {
        process: CString,
        args: Vec<CString>,
    }

    impl Ptrace {
        /// Create a new instance of `Ptrace`
        pub fn new(process: &str, process_name: &str, args: &[&str]) -> PTraceResult<Self> {

            let mut cargs = Vec::new();
            cargs.push(CString::new(process_name)?);
            for a in args {
                cargs.push(CString::new(*a)?);
            }

            Ok(Self {
                process: CString::new(process)?,
                args: cargs,
            })
        }

        /// Fork and spawn a child for debugging
        pub fn inital_spawn_child(&self) -> Process {
            let child = unsafe { libc::fork() };
            let child_proc = Process(child);

            if child == 0 {
                let _child_pid = unsafe { libc::getpid() };
                // Mark the child for tracing
                Process::ptrace_traceme();

                // Mark that this process should not use ASLR so we can set breakpoints easily
                unsafe { libc::personality(libc::ADDR_NO_RANDOMIZE as u64) };

                let mut pointers = Vec::new();
                for arg in &self.args {
                    pointers.push(arg.as_ptr());
                }
                pointers.push(core::ptr::null_mut() as *const _);

                // Spawn the child
                let r = unsafe { libc::execv(self.process.as_ptr(),  pointers.as_ptr()) };

                // Note: this drop forces the vec to not be dropped until after the evecv finishes, which will never happen if it works
                drop(pointers);
                panic!("Failed to start subprocess: {} {}", r, unsafe { *libc::__errno_location() });
            }

            // Wait for the new process to start
            child_proc.wait_for();

            unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, child, 0, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_TRACEEXIT) };

            child_proc
        }
    }
}
