use crate::{Process};

/// Represent a single breakpoint
#[derive(Debug, Copy, Clone)]
pub struct Breakpoint {
    /// The original value of the byte that this breakpoint replaced, None if the value is missing
    original_byte: Option<u8>,
    /// The address this breakpoint is attached to
    pub address: usize
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

        // Get the original instruction
        let original_instruction = child.ptrace_peektext(self.address) as u64;
        // Save the original byte
        self.original_byte = Some((original_instruction & 0xFF) as u8);
        // Path the instruction
        let patched_instruction = (original_instruction & 0xFFFF_FFFF_FFFF_FF00u64) | 0xCC;
        // Write the patched instruction to the text section
        unsafe { libc::ptrace(libc::PTRACE_POKETEXT, child.0, self.address, patched_instruction) };
        // println!("Installed bp @ 0x{:x}", self.address);
        return true;
    }

    /// Uninstall the breakpoint from the target
    /// Returns true if the original instruction was restored
    /// Returns false if the breakpoint is not installed
    pub fn uninstall(&mut self, child: Process) -> bool {
        return if let Some(original_byte) = self.original_byte {
            // Get the modified instruction that contains int3 at start
            let original_instruction = unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, child, self.address, 0) } as u64;
            // Put the original byte that was overwritten with int3 back
            let patched_instruction = (original_instruction & 0xFFFF_FFFF_FFFF_FF00u64) | (original_byte as u64);
            // Put the instruction back in the binary
            unsafe { libc::ptrace(libc::PTRACE_POKETEXT, child, self.address, patched_instruction) };

            self.original_byte = None;

            true
        } else {
            false
        }
    }
}
