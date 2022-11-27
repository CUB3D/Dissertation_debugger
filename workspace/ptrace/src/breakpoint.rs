use crate::Process;

/// Represent a single breakpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Breakpoint {
    #[cfg(target_arch = "x86_64")]
    /// The original value of the byte that this breakpoint replaced, None if the value is missing
    pub original_byte: Option<u8>,
    #[cfg(target_arch = "aarch64")]
    /// The original value of the bytes that this breakpoint replaced, None if the value is missing
    pub original_byte: Option<u32>,
    /// The address this breakpoint is attached to
    pub address: usize,
}

impl Breakpoint {
    pub fn new(address: usize) -> Self {
        Self {
            address,
            original_byte: None,
        }
    }

    /// Install the given breakpoint, enabling it
    /// Returns true if the breakpoint was installed correctly and the instruction was patched
    /// Returns false if the breakpoint could not be installed, e.g if it is already installed
    pub fn install(&mut self, child: Process) -> bool {
        // Dont install if already installed
        if self.original_byte.is_some() {
            return false;
        }

        #[cfg(target_arch = "x86_64")]
        {
            // Get the original instruction
            return if let Some(original_instruction) = child.ptrace_peektext_safe(self.address) {
                // Save the original byte
                self.original_byte = Some((original_instruction & 0xFF) as u8);
                // Path the instruction
                let patched_instruction = (original_instruction & 0xFFFF_FFFF_FFFF_FF00u64) | 0xCC;
                // Write the patched instruction to the text section
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_POKETEXT,
                        child.0,
                        self.address,
                        patched_instruction,
                    )
                };
                // println!("Installed bp @ 0x{:x}", self.address);
                true
            } else {
                false
            };
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Get the original instruction
            return if let Some(original_instruction) = child.ptrace_peektext_safe(self.address) {
                // Save the original byte
                self.original_byte = Some((original_instruction & 0xFFFF_FFFF) as u32);
                // Path the instruction
                let patched_instruction = (original_instruction & 0xFFFF_FFFF_0000_0000u64) | 0xD4200000;
                // Write the patched instruction to the text section
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_POKETEXT,
                        child.0,
                        self.address,
                        patched_instruction,
                    )
                };
                // println!("Installed bp @ 0x{:x}", self.address);
                true
            } else {
                false
            };
        }
    }

    /// Uninstall the breakpoint from the target
    /// Returns true if the original instruction was restored
    /// Returns false if the breakpoint is not installed
    pub fn uninstall(&mut self, child: Process) -> bool {
        #[cfg(target_arch = "x86_64")]
        return if let Some(original_byte) = self.original_byte {
            // Get the modified instruction that contains int3 at start
            let original_instruction =
                unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, child, self.address, 0) } as u64;
            // Put the original byte that was overwritten with int3 back
            let patched_instruction =
                (original_instruction & 0xFFFF_FFFF_FFFF_FF00u64) | (original_byte as u64);
            // Put the instruction back in the binary
            unsafe {
                libc::ptrace(
                    libc::PTRACE_POKETEXT,
                    child,
                    self.address,
                    patched_instruction,
                )
            };

            self.original_byte = None;

            true
        } else {
            false
        };

        #[cfg(target_arch = "aarch64")]
        return if let Some(original_byte) = self.original_byte {
            // Get the modified instruction that contains int3 at start
            let original_instruction =
                unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, child, self.address, 0) } as u64;
            // Put the original byte that was overwritten with int3 back
            let patched_instruction =
                (original_instruction & 0xFFFF_FFFF_0000_0000u64) | (original_byte as u64);
            // Put the instruction back in the binary
            unsafe {
                libc::ptrace(
                    libc::PTRACE_POKETEXT,
                    child,
                    self.address,
                    patched_instruction,
                )
            };

            self.original_byte = None;

            true
        } else {
            false
        };
    }
}
