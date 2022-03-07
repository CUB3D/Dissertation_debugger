//! Handling of processes

use crate::UserRegs;
use crate::FpRegs;
use crate::WaitStatus;

/// A process identifier (pid)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Process(pub i32);

#[cfg(target_os = "linux")]
impl Process {
    /// Wait for the current process, returning the status
    pub fn wait_for(&self) -> WaitStatus {
        let mut status = 0;
        unsafe { libc::waitpid(self.0, &mut status as *mut _, libc::__WALL)};
        WaitStatus(status)
    }

    /// Wait for any process, returning the pid and the status
    /// Equivelent to Proceess(-1).wait_for() execpt this returns the pid that stopped
    pub fn wait_any() -> (Process, WaitStatus) {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status as *mut _, libc::__WALL)};
        (Process(pid), WaitStatus(status))
    }

    /// Read a null terminated string from the given address in the address space of this process
    /// SAFTEY: This function will continue reading memory until either an error, or a null byte is reached
    /// It is up to the caller to ensure that the given address points to a valid string in the address space of the target
    /// also see 'ptrace_read_string'
    pub unsafe fn read_string(&self, address: i64) -> String {
        crate::ptrace_read_string(self.0, address)
    }

    /// Start tracing the current process with ptrace
    pub fn ptrace_traceme() {
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)});
    }

    /// Continue the process
    pub fn ptrace_cont(&self) {
        unsafe { libc::ptrace(libc::PTRACE_CONT, self.0, 0, 0)};
    }

    /// Detach from the process
    pub fn ptrace_detach(&self) {
        unsafe { libc::ptrace(libc::PTRACE_DETACH, self.0, 0, 0)};
    }

    /// Interrupt the process, only works on processes attached with PTRACE_SIEZE
    pub fn ptrace_interrupt(&self) {
        unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, self.0, 0, 0)};
    }

    /// Continue the process, waiting for the next syscall
    pub fn ptrace_syscall(&self) {
        unsafe { libc::ptrace(libc::PTRACE_SYSCALL, self.0, 0, 0)};
    }

    /// Single step the process
    pub fn ptrace_singlestep(&self) {
        unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, self.0, 0, 0)};
    }

    pub fn ptrace_syscall_signal(&self, signal: i32) {
        unsafe { libc::ptrace(libc::PTRACE_SYSCALL, self.0, 0, signal)};
    }
    pub fn ptrace_geteventmsg(&self) -> usize {
        let mut msg = 0;
        unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, self.0, 0, &mut msg as *mut usize)};
        msg
    }

    /// Get the user registers of the process
    pub fn ptrace_getregs(&self) -> Box<UserRegs> {
        let mut regs = Box::<UserRegs>::default();
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_GETREGS, self.0, 0, regs.as_mut() as *mut _)});
        regs
    }

    /// Get the fp regs of the process
    pub fn ptrace_getfpregs(&self) -> Box<FpRegs> {
        let mut fpregs = unsafe { Box::<FpRegs>::new_zeroed().assume_init() };
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_GETFPREGS, self.0, 0, fpregs.as_mut() as *mut _)});
        fpregs
    }

    /// Set the user regs of the process
    pub fn ptrace_setregs(&mut self, regs: Box<UserRegs>) {
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_SETREGS, self.0, 0, regs.as_ref() as *const _)});
    }

    /// Get the original value of rax, this will contain the id of the syscall being executed on linux when a syscall trap event is raised
    pub fn ptrace_getreg_origrax(&self) -> i64 {
        unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, self.0, 8*libc::ORIG_RAX, 0)}
    }

    /// Read a u64 from the given address in the process address space
    pub fn ptrace_peektext(&self, addr: usize) -> u64 {
        let val = unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, self.0, addr, 0) } as u64;
        return val;
    }

    /// Send a sigstop to the process
    pub fn sigstop(&self) {
        unsafe { libc::kill(self.0, libc::SIGSTOP) };
    }
}