#![feature(new_uninit)]

#[cfg(target_os = "linux")]
pub use linux_ptrace::*;
#[cfg(all(target_os = "linux", feature = "breakpoints"))]
pub mod breakpoint;
#[cfg(all(target_os = "linux", feature = "event_debugger"))]
pub mod event_debugger;
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
pub mod types;

#[cfg(all(target_os = "linux", feature = "breakpoints"))]
pub use breakpoint::*;
#[cfg(target_os = "linux")]
pub use linux_memory_map::*;
#[cfg(target_os = "linux")]
pub use process::*;
#[cfg(target_os = "linux")]
pub use types::*;

#[cfg(target_os = "linux")]
mod linux_ptrace {
    use crate::process::Process;
    use std::error::Error;
    use std::ffi::CString;

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
        pub fn new<T: AsRef<str>>(process: &str, process_name: &str, args: &[T]) -> PTraceResult<Self> {
            let mut cargs = Vec::new();
            cargs.push(CString::new(process_name)?);
            for a in args {
                let a: &str = a.as_ref();
                cargs.push(CString::new(a)?);
            }

            Ok(Self {
                process: CString::new(process)?,
                args: cargs,
            })
        }

        /// Fork and spawn a child for debugging
        /// child_callback will be executed by the forked child before excve'ing
        pub fn inital_spawn_child<F: FnOnce()>(&self, child_callback: Option<F>) -> Process {
            let child = unsafe { libc::fork() };
            let child_proc = Process(child);

            if child == 0 {
                // Mark the child for tracing
                Process::ptrace_traceme();

                // Mark that this process should not use ASLR so we can set breakpoints easily
                unsafe { libc::personality(libc::ADDR_NO_RANDOMIZE as u64) };

                // Call the callback if it exists
                if let Some(callback) = child_callback {
                    callback();
                }

                // Convert args into a null terminated list of ptrs
                let mut pointers = Vec::new();
                for arg in &self.args {
                    pointers.push(arg.as_ptr());
                }
                pointers.push(core::ptr::null_mut() as *const _);

                // Spawn the child
                let r = unsafe { libc::execv(self.process.as_ptr(), pointers.as_ptr()) };

                // Note: this drop forces the vec to not be dropped until after the evecv finishes, which will never happen if it works
                drop(pointers);
                panic!("Failed to start subprocess: {} {}", r, unsafe {
                    *libc::__errno_location()
                });
            }

            // Wait for the new process to start
            child_proc.wait_for();

            unsafe {
                libc::ptrace(
                    libc::PTRACE_SETOPTIONS,
                    child,
                    0,
                    libc::PTRACE_O_EXITKILL
                        | libc::PTRACE_O_TRACESYSGOOD
                        | libc::PTRACE_O_TRACECLONE
                        | libc::PTRACE_O_TRACEEXEC
                        | libc::PTRACE_O_TRACEFORK
                        | libc::PTRACE_O_TRACEVFORK
                        | libc::PTRACE_O_TRACEEXIT,
                )
            };

            child_proc
        }
    }
}

#[test]
fn t() {
    println!("Hi");
}
