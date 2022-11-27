#[cfg(target_arch = "aarch64")]
/// Translated to rust from <arch/aarch64/include/uapi/asm/ptrace.h> user_pt_regs
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct UserRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(target_arch = "x86_64")]
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FpRegs {
    /// FPU Control Word
    pub cwd: libc::c_ushort,
    /// FPU Status Word
    pub swd: libc::c_ushort,
    /// FPU Tag Word
    pub ftw: libc::c_ushort,
    /// Last Instruction Opcode
    pub fop: libc::c_ushort,
    /// Instruction Pointer
    pub rip: libc::c_ulonglong,
    /// Data Pointer
    pub rdp: libc::c_ulonglong,
    /// MXCSR Register State
    pub mxcsr: libc::c_uint,
    /// MXCSR Mask
    pub mxcr_mask: libc::c_uint,
    /// 8*10 bytes for each FP-reg = 80 bytes
    /// overalaps with 16 * 8 for each MMX register = 128 bytes
    pub st_space: [libc::c_uint; 32],
    /// 32*8 for each ymm register = 256 bytes
    /// overlaps with 16 * 8 for each xmm register (xmm0 = ymm0 lower half)
    pub xmm_space: [libc::c_uint; 64],
    pub padding: [libc::c_uint; 24],
}

/// Representation of the return value of waitpid (2)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WaitStatus(pub i32);
impl WaitStatus {
    pub fn wstatus(&self) -> i32 {
        self.0 & 127
    }

    /// True if the process stopped due to a signal
    pub fn wifstopped(&self) -> bool {
        self.wstatus() == 127
    }

    /// The signal number that caused the process to stop
    pub fn wstopsig(&self) -> i32 {
        (self.0 >> 8) & 0xFF
    }

    /// True if the process was terminated by a signal
    pub fn wifsignaled(&self) -> bool {
        self.wstatus() != 127 && self.wstatus() != 0
    }

    /// The signal that terminated the process
    pub fn wtermsig(&self) -> i32 {
        self.wstatus()
    }

    /// True if the process terminated
    pub fn wifexited(&self) -> bool {
        self.wstatus() == 0
    }

    /// The exit status of the process, only defined if wifexited == true
    pub fn wexitstatus(&self) -> i32 {
        self.0 >> 8
    }
}
