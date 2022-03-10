use core::ops::Range;
pub use linux_memory_map::*;

/// Translated to rust from <arch/x86/include/asm/user_64.h>
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UserRegs {
    pub r15: libc::c_ulonglong,
    pub r14: libc::c_ulonglong,
    pub r13: libc::c_ulonglong,
    pub r12: libc::c_ulonglong,
    pub bp: libc::c_ulonglong,
    pub bx: libc::c_ulonglong,
    pub r11: libc::c_ulonglong,
    pub r10: libc::c_ulonglong,
    pub r9: libc::c_ulonglong,
    pub r8: libc::c_ulonglong,
    pub ax: libc::c_ulonglong,
    pub cx: libc::c_ulonglong,
    pub dx: libc::c_ulonglong,
    pub si: libc::c_ulonglong,
    pub di: libc::c_ulonglong,
    pub orig_ax: libc::c_ulonglong,
    pub ip: libc::c_ulonglong,
    pub cs: libc::c_ulonglong,
    pub flags: libc::c_ulonglong,
    pub sp: libc::c_ulonglong,
    pub ss: libc::c_ulonglong,
    pub fs_base: libc::c_ulonglong,
    pub gs_base: libc::c_ulonglong,
    pub ds: libc::c_ulonglong,
    pub es: libc::c_ulonglong,
    pub fs: libc::c_ulonglong,
    pub gs: libc::c_ulonglong,
}

/// A syscall argument
#[derive(Debug, Clone)]
pub enum SyscallArg {
    /// A path to a file
    FilePath(String),
    /// A reference to an open file descriptor
    FileDescriptor(i64),
    /// A process id
    ProcessId(u64),
    /// A memory address
    Address(u64),
    /// A generic string
    String(String),
    /// A generic u64
    U64(u64),
}

/// A syscall invocation
#[derive(Debug, Clone)]
pub struct Syscall {
    /// The name of the syscall that was executed
    pub name: String,
    /// The syscall arguments
    pub args: Vec<SyscallArg>,
}

#[derive(Clone, Debug)]
pub struct CallStack(pub Vec<StackFrame>);
#[derive(Clone, Debug)]
pub struct StackFrame {
    pub addr: usize,
    pub description: String,
}
