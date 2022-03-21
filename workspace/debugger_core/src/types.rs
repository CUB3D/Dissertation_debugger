pub use linux_memory_map::*;
pub use ptrace::types::UserRegs;

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
