#![feature(new_uninit)]

use std::ffi::CString;
use std::error::Error;
use std::collections::BTreeMap;
use std::ops::{Range, Deref};
use std::io::{Seek, SeekFrom, Read, Write};
use std::fmt::Debug;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    WriteFile {fd: i64, data: Vec<u8>},
}


/// Read a null-terminated (cstring) from the process `child` at address `addr`,
/// # Safety
/// Unsafe as the given pointer is not checked for either alignment or the existance of a valid null-terminated string
pub unsafe fn ptrace_read_string(child : i32, addr: i64) -> String {
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

#[derive(Debug, Clone)]
pub struct MemoryMap(pub Vec<MemoryMapEntry>);
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MemoryMapEntryPermissionsKind {
    Private,
    Shared
}
impl core::fmt::Display for MemoryMapEntryPermissionsKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Private => write!(f, "private"),
            Shared => write!(f, "shared"),
        }
    }
}
#[derive(Copy, Clone, Debug)]
pub struct MemoryMapEntryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub kind: MemoryMapEntryPermissionsKind
}
#[derive(Clone, Debug)]
pub struct MemoryMapEntry {
    pub range: Range<usize>,
    pub permissions: MemoryMapEntryPermissions,
    pub path: String,
}

#[cfg(feature = "breakpoints")]
pub fn get_memory_map(pid: i32) -> Option<MemoryMap> {
    // println!("Getting map for {}", pid);
    let content = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

    let mut map = Vec::new();
    for line in content.split('\n') {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(' ');
        let addr_range = parts.next()?;
        let mut addr_range_parts = addr_range.split('-');
        let addr_range_start = usize::from_str_radix(addr_range_parts.next()?, 16).ok()?;
        let addr_range_end = usize::from_str_radix(addr_range_parts.next()?, 16).ok()?;


        let perms = parts.next()?;
        let _offset = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let pathname = parts.last()?;


        map.push(MemoryMapEntry {
            range: addr_range_start..addr_range_end,
            permissions: MemoryMapEntryPermissions {
                read: perms.contains('r'),
                write: perms.contains('w'),
                execute: perms.contains('x'),
                kind: if perms.contains('p') {
                    MemoryMapEntryPermissionsKind::Private
                } else if perms.contains('s') {
                    MemoryMapEntryPermissionsKind::Shared
                } else {
                    panic!("Unknown permissions: {}", perms);
                }
            },
            path: pathname.to_string()
        })
    }

    Some(MemoryMap(map))
}

#[derive(Clone, Debug)]
struct FakeFile {
    data: Vec<u8>,
    pos: usize
}

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

// #[cfg(feature = "snapshots")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FpRegs {
    pub cwd: libc::c_ushort,
    pub swd: libc::c_ushort,
    pub ftw: libc::c_ushort,
    pub fop: libc::c_ushort,
    pub rip: libc::c_ulonglong,
    pub rdp: libc::c_ulonglong,
    pub mxcsr: libc::c_uint,
    pub mxcr_mask: libc::c_uint,
    pub st_space: [libc::c_uint; 32],
    pub xmm_space: [libc::c_uint; 64],
    pub padding: [libc::c_uint; 24],
}

#[cfg(feature = "snapshots")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    regs: Box<UserRegs>,
    fpregs: Box<FpRegs>,
    /// Copy of the entire process memory, format is [(data, source memory range, path)]
    memory: Vec<(Vec<u8>, Range<usize>, String)>,
    vfs: VFS,
}

/// The action to take when a breakpoint is triggered
#[cfg(feature = "breakpoints")]
#[derive(Copy, Clone, Debug)]
pub enum BreakpointAction {
    /// Take a snapshot of the process state
    RestoreSnapshot,
    /// Restore a snapshot of the process state taken at an earlier point
    SaveSnapshot,
}

const VFS_FD_BASE: i64 = 13371337;

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
struct FileHandle {
    file_id: usize,
    pos: i64,
}

/// A VirtualFileSystem
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct VFS {
    files: Vec<Vec<u8>>,
    path_mocks: BTreeMap<String, usize>,
    //TODO: need to store the pos in the inode map, not in the file,
    inode_map: BTreeMap<i64, FileHandle>
}

impl VFS {
    fn get_file_index_by_path(&self, path: &str) -> Option<usize> {
        self.path_mocks.get(path).copied()
    }
    fn get_file_index_by_fd(&mut self, fd: &i64) -> Option<&mut FileHandle> {
        self.inode_map.get_mut(fd)
    }
    fn get_file_content_by_fd(&mut self, fd: &i64) -> Option<Vec<u8>> {
        let index = self.get_file_index_by_fd(fd).copied()?;
        self.files.get(index.file_id).cloned()
    }
    pub fn get_file_content_by_path(&mut self, path: &str) -> Option<Vec<u8>> {
        let index = self.get_file_index_by_path(path)?;
        self.files.get(index).cloned()
    }
    fn fd_is_path(&mut self, fd: i64, path: &str) -> bool {
        if let Some(index) = self.get_file_index_by_path(path) {
            if let Some(fh) = self.inode_map.get(&fd) {
                return fh.file_id == index;
            }
        }
        false
    }

    fn has_path(&mut self, path: &str) -> bool {
        self.get_file_index_by_path(path).is_some()
    }
    fn has_fd(&mut self, fd: &i64) -> bool {
        self.get_file_index_by_fd(fd).is_some()
    }

    fn openat(&mut self, path: &str) -> Option<i64> {
        let file_id = self.get_file_index_by_path(path)?;

        let mut fd = VFS_FD_BASE;
        while self.inode_map.contains_key(&fd) {
            fd += 1;
        }

        self.inode_map.insert(fd, FileHandle {
            file_id,
            pos: 0,
        });

        Some(fd)
    }

    fn get_pos(&self, fd: i64) -> Option<i64> {
        Some(self.inode_map.get(&fd)?.pos)
    }

    fn set_pos(&mut self, fd: i64, pos: i64) -> Option<()> {
        self.inode_map.get_mut(&fd)?.pos = pos;
        Some(())
    }

    fn get_len(&self, fd: i64) -> Option<usize> {
        let file_id = self.inode_map.get(&fd)?.file_id;
        Some(self.files.get(file_id)?.len())
    }

    /// Read one byte from fd
    fn read_u8(&mut self, fd: i64) -> Option<u8> {
        let mut file_handle = self.inode_map.get_mut(&fd)?;
        let file = self.files.get(file_handle.file_id)?;
        let data = file.get(file_handle.pos as usize)?;
        file_handle.pos += 1;
        Some(*data)
    }

    /// Write one byte to the fd
    fn write_u8(&mut self, fd: i64, new_data: u8) -> Option<()> {
        let mut file_handle = self.inode_map.get_mut(&fd)?;
        let file = self.files.get_mut(file_handle.file_id)?;
        file.push(new_data);
        file_handle.pos += 1;

        Some(())
    }

    fn truncate(&mut self, path: &str) -> Option<()> {
        let file_id = self.path_mocks.get(path).copied()?;
        let file_content = self.files.get_mut(file_id)?;
        if !file_content.is_empty() {
            println!("[warn]: mock file {} truncated with data", path);
        }
        file_content.clear();
        Some(())
    }

    fn close(&mut self, fd: i64) {
        self.inode_map.remove(&fd);
    }

    /// Mock the existance of a file with given contents,
    /// this will modify the following syscalls:
    /// - openat will return a mocked file descriptor and no longer return ENOENT
    /// - stat will no longer return ENOENT
    /// - lseek will operate on the mocked file structure
    /// - read will read from the mocked file
    /// - TODO: close will operate on the mocked file structure
    pub fn mock_file(&mut self, paths: &[&str], data: Vec<u8>) {
        let file_id = self.files.len();
        self.files.push(data);

        for path in paths {
            self.path_mocks.insert(path.to_string(), file_id);
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct WaitStatus(pub i32);
impl WaitStatus {
    pub fn wstatus(&self) -> i32 {
        self.0 & 127
    }

    pub fn wifstopped(&self) -> bool {
        self.wstatus() == 127
    }

    pub fn wstopsig(&self) -> i32 {
        (self.0 >> 8) & 0xFF
    }

    pub fn wifsignaled(&self) -> bool {
        self.wstatus() != 127 && self.wstatus() != 0
    }

    pub fn wtermsig(&self) -> i32 {
        self.wstatus()
    }

    pub fn wifexited(&self) -> bool {
        self.wstatus() == 0
    }

    pub fn wexitstatus(&self) -> i32 {
        self.0 >> 8
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Process(pub i32);

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

    pub fn ptrace_traceme() {
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0)});
    }
    pub fn ptrace_cont(&self) {
        unsafe { libc::ptrace(libc::PTRACE_CONT, self.0, 0, 0)};
    }
    pub fn ptrace_detach(&self) {
        unsafe { libc::ptrace(libc::PTRACE_DETACH, self.0, 0, 0)};
    }
    pub fn ptrace_interrupt(&self) {
        unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, self.0, 0, 0)};
    }
    pub fn ptrace_syscall(&self) {
        unsafe { libc::ptrace(libc::PTRACE_SYSCALL, self.0, 0, 0)};
    }
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
    pub fn ptrace_getregs(&self) -> Box<UserRegs> {
        let mut regs = Box::<UserRegs>::default();
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_GETREGS, self.0, 0, regs.as_mut() as *mut _)});
        regs
    }
    pub fn ptrace_getfpregs(&self) -> Box<FpRegs> {
        let mut fpregs = unsafe { Box::<FpRegs>::new_zeroed().assume_init() };
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_GETFPREGS, self.0, 0, fpregs.as_mut() as *mut _)});
        fpregs
    }
    pub fn ptrace_setregs(&mut self, regs: Box<UserRegs>) {
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_SETREGS, self.0, 0, regs.as_ref() as *const _)});
    }
    pub fn ptrace_getreg_origrax(&self) -> i64 {
        unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, self.0, 8*libc::ORIG_RAX, 0)}
    }
    pub fn ptrace_peektext(&self, addr: usize) -> u64 {
        let val = unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, self.0, addr, 0) } as u64;
        return val;
    }

}

/// Represent a single breakpoint
#[cfg(feature = "breakpoints")]
#[derive(Debug, Copy, Clone)]
pub struct Breakpoint {
    /// The original value of the byte that this breakpoint replaced, None if the value is missing
    original_byte: Option<u8>,
    /// The action to take when this breakpoint is triggered
    action: BreakpointAction,
    /// The address this breakpoint is attached to
    pub address: usize
}

impl Breakpoint {
    pub fn new(address: usize) -> Self {
        Self {
            address,
            action: BreakpointAction::SaveSnapshot,
            original_byte: None,
        }
    }

    /// Install the given breakpoint, enabling it
    /// Returns true if the breakpoint was installed correctly and the instruction was patched
    /// Returns false if the breakpoint could not be installed, e.g if it is already installed
    pub fn install(&mut self, child: Process) -> bool {
        /*let mm = get_memory_map(child).unwrap();
        // Process load address will be the first entry in the memory map
        let process_load_address = mm.0.first().unwrap().range.start;
        println!("PLA = 0x{:X}", process_load_address);*/


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
        println!("Installed bp @ 0x{:x}", self.address);
        return true;
    }

    /// Uninstall the breakpoint from the target
    /// Returns true if the original instruction was restored
    /// Returns false if the breakpoint is not installed
    pub fn uninstall(&mut self, child: Process) -> bool {
        if let Some(original_byte) = self.original_byte {
            // Get the modified instruction that contains int3 at start
            let original_instruction = unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, child, self.address, 0) } as u64;
            // Put the original byte that was overwritten with int3 back
            let patched_instruction = (original_instruction & 0xFFFF_FFFF_FFFF_FF00u64) | (original_byte as u64);
            // Put the instruction back in the binary
            unsafe { libc::ptrace(libc::PTRACE_POKETEXT, child, self.address, patched_instruction) };

            self.original_byte = None;

            return true;
        } else {
            return false;
        }
    }
}

type PTraceResult<T> = Result<T, Box<dyn Error>>;

pub struct Ptrace {
    process: CString,
    process_name: CString,
    arg: CString,

    /// The virtual file system
    vfs: VFS,

    #[cfg(feature = "snapshots")]
    snapshot: Option<Snapshot>,

    #[cfg(feature = "breakpoints")]
    breakpoints: BTreeMap<usize, Breakpoint>,

    #[cfg(feature = "child_processes")]
    processes: BTreeMap<i32, ()>,
}

impl Ptrace {
    /// Create a new instance of `Ptrace`
    pub fn new(process: &str, process_name: &str, arg: &str) -> PTraceResult<Self> {
        Ok(Self {
            process: CString::new(process)?,
            process_name: CString::new(process_name)?,
            arg: CString::new(arg)?,
            #[cfg(feature = "snapshots")]
            snapshot: None,
            vfs: Default::default(),
            #[cfg(feature = "breakpoints")]
            breakpoints: Default::default(),
            #[cfg(feature = "child_processes")]
            processes: Default::default(),
        })
    }

    pub fn vfs_mut(&mut self) -> &mut VFS {
        &mut self.vfs
    }

    #[cfg(snapshots)]
    /// Take a snapshot of the given process, snapshots include the full register (integer, fp) state + stack state
    fn snapshot(&mut self, child: i32) -> Snapshot {
        // Create a fresh memory map
        let map = get_memory_map(child).unwrap();

        println!("Creating snapshot");

        let mut regs = Box::<UserRegs>::default();
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_GETREGS, child, 0, regs.as_mut() as *mut _)});
        // Safety: Massive hack to allocate FpRegs without having to allocate it on stack at all
        let mut fpregs = unsafe { Box::<FpRegs>::new_zeroed().assume_init() };
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_GETFPREGS, child, 0, fpregs.as_mut() as *mut _)});

        println!("[snapshot] memory");

        let mut memory = Vec::new();
        for ent in &map.0 {
            // No point saving read-only memory
            if !ent.permissions.write {
                continue;
            }
            println!("Backing up mem section: {}", ent.path);
            let mut mem_file = std::fs::File::open(format!("/proc/{}/mem", child)).expect("No mem?");
            let mut mem = vec![0u8; ent.range.end - ent.range.start];
            mem_file.seek(SeekFrom::Start(ent.range.start as u64)).expect("Seek failed");
            //TODO:
            let _ = mem_file.read_exact(&mut mem);//.expect("Failed to read memory range");

            memory.push((mem, ent.range.clone(), ent.path.clone()));
        }

        Snapshot {
            regs,
            fpregs,
            memory,
            vfs: self.vfs.clone(),
        }
    }

    #[cfg(snapshots)]
    fn snapshot_restore(&mut self, child: i32, snp: Snapshot) {
        println!("Restoring");


        println!("Restoring memory");
        for (data, src_range, path) in snp.memory {
            println!("Restoring: {}", path);
            let mut mem_file = std::fs::OpenOptions::new().write(true).open(format!("/proc/{}/mem", child)).expect("No mem?");
            mem_file.seek(SeekFrom::Start(src_range.start as u64)).expect("Seek failed");
            //TODO:
            let _ = mem_file.write_all(&data);//.expect("Failed to write memory range");
        }

        // Restore the saved registers
        let regs = snp.regs;
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_SETREGS, child, 0, regs.as_ref() as *const _)});
        let fpregs = snp.fpregs;
        assert_ne!(-1, unsafe { libc::ptrace(libc::PTRACE_SETFPREGS, child, 0, fpregs.as_ref() as *const _)});

        self.vfs = snp.vfs;

        println!("Continuing");
    }

    /// Fork and spawn a child for debugging
    pub fn inital_spawn_child(&self) -> Process {
        let child = unsafe { libc::fork() };
        let child_proc = Process(child);

        if child == 0 {
            let child_pid = unsafe { libc::getpid() };
            println!("Child pid = {}", child_pid);
            // Mark the child for tracing
            Process::ptrace_traceme();

            // Mark that this process should not use ASLR so we can set breakpoints easily
            unsafe { libc::personality(libc::ADDR_NO_RANDOMIZE as u64) };

            // Spawn the child
            let r = unsafe { libc::execl(self.process.as_ptr(), self.process_name.as_ptr(), self.arg.as_ptr(), 0)};
            panic!("Failed to start subprocess: {} {}", r, unsafe { *libc::__errno_location()});
        }

        // Wait for the new process to start
        child_proc.wait_for();

        unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, child, 0, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD)};

        return child_proc;
    }

    /// Fork and spawn a child under the debugger
    pub fn spawn(&mut self, mut callback: Box<dyn FnMut(&mut Ptrace, Event)>) {
        let child_proc = self.inital_spawn_child();
        let child = child_proc.0;

        #[cfg(feature = "breakpoints")]
        {
            // Install all the breakpoints
            for (bp_pc, bp) in &mut self.breakpoints {
                bp.install(child_proc);
            }
        }

        // Resume the process
        child_proc.ptrace_syscall();

        // Are we currently processing a syscall
        let mut in_call = false;

        let mut rax_overwrite = Option::<i64>::None;

        loop {
            let err = unsafe { *libc::__errno_location()};
            if err != 0 {
                println!("found errno set {}", err);
                unsafe { *libc::__errno_location() = 0};
            }

            // Wait for next event
            #[cfg(feature = "child_processes")]
            let status = {
                let (pid, status) = Process::wait_any();

                // We only care about events from the main thread
                if pid.0 != child {
                    pid.ptrace_cont();
                    continue;
                }
                status
            };
            #[cfg(not(feature = "child_processes"))]
            let status = {
                child_proc.wait_for()
            };

            #[cfg(feature = "child_processes")]
            let mut si: libc::siginfo_t = *unsafe {Box::<libc::siginfo_t>::new_zeroed().assume_init()}.deref();

            // Get registers
            let original_rax = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, 8*libc::ORIG_RAX, 0)};
            // let rax = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, 8*libc::RAX, 0)};
            let rdx = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, 8*libc::RDX, 0)};
            let rsi = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, 8*libc::RSI, 0)};
            let rdi = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, 8*libc::RDI, 0)};
            let rip = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, 8 * libc::RIP, 0) };

            if status.wifstopped() {
                let stopsig = status.wstopsig();
                // println!("ss {}", stopsig);
                if stopsig == (libc::SIGTRAP | 0x80) {
                    // println!("syscall {} @ 0x{:x}", original_rax, rip as usize - process_load_address - 1);

                    if !in_call {
                        match original_rax {
                            libc::SYS_close => {
                                if self.vfs.has_fd(&rdi) {
                                    // println!("close({}) @ 0x{:x}", rdi, rip);

                                    // if self.vfs.inode_map.get(&rdi).unwrap().file_id == self.vfs.get_file_index_by_path("./test.swf").unwrap() {
                                    //     loop {
                                    //         unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, child, 0, 0)};
                                    //         child_proc.wait_for();
                                    //         let rip = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, child, libc::RIP * 8, 0)};
                                    //         println!("0x{:x}", rip);
                                    //     }
                                    // }
                                    //     // Wait for the syscall-exit
                                    //     child_proc.ptrace_syscall();
                                    //     child_proc.wait_for();
                                    //
                                    //     // Single step the return back to the caller
                                    //     unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, child, 0, 0) };
                                    //     child_proc.wait_for();
                                    //
                                    //     if let Some(sn) = self.snapshot.clone() {
                                    //         self.snapshot_restore(child, sn.clone());
                                    //     }
                                    //
                                    //     // Wait for next syscall
                                    //     child_proc.ptrace_syscall();
                                    //
                                    //     continue;
                                    // }

                                    self.vfs.close(rdi);
                                }
                            }
                            libc::SYS_write => {
                                // rdi => fd
                                // rsi => buf
                                // rdx => count

                                if self.vfs.has_fd(&rdi) {
                                    // Copy the data from the buffer in the process, to the fake file
                                    for i in 0..rdx {
                                        let byte = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, child, rsi+i, 0) };
                                        let lo = (byte & 0xFF) as u8;
                                        self.vfs.write_u8(rdi, lo);
                                    }

                                    in_call = true;
                                    rax_overwrite = Some(rdx);
                                    println!("write({}, {}, {})", rdi, rsi, rdx);

                                    let data = self.vfs.get_file_content_by_fd(&rdi).unwrap();
                                    callback(self, Event::WriteFile { fd: rdi ,data})
                                }
                            }
                            libc::SYS_truncate => {
                                let str_arg = unsafe { ptrace_read_string(child, rdi) };

                                if self.vfs.has_path(&str_arg) {
                                    self.vfs.truncate(&str_arg).unwrap();
                                    in_call = true;
                                    rax_overwrite = Some(0);
                                    println!("truncate({}, {})", str_arg, rsi);
                                }
                            }
                            libc::SYS_stat => {
                                // Read the first arg
                                let str_arg = unsafe { ptrace_read_string(child, rdi) };

                                // Check if the file is in the VFS
                                if self.vfs.has_path(&str_arg) {
                                    in_call = true;
                                    // set RAX to 0, indicating that the stat() call worked, meaning we should try to open the file
                                    rax_overwrite = Some(0);
                                    println!("stat({})", str_arg);
                                }
                            }
                            libc::SYS_openat => {
                                // Convert the first argument (fd) to a name if this value has been reserved
                                let fd_name = match rdi as i32 {
                                    -100 => "AT_FDCWD".to_string(),
                                    _ => format!("{}", rdi)
                                };

                                // Read the second arg
                                let str_arg = unsafe { ptrace_read_string(child, rsi) };


                                if self.vfs.has_path(&str_arg) {
                                    let file_descriptor = self.vfs.openat(&str_arg).expect("Failed to openat");
                                    in_call = true;
                                    // Set RAX to `SPOOFED_FILE_DESCRIPTOR` indicating that the call worked, we will spoof reads from this fd
                                    rax_overwrite = Some(file_descriptor);
                                    println!("openat(fd_name={}, path={}, {})", fd_name, str_arg, rdx);
                                }

                                // if str_arg=="/home/cub3d/projects/snapshotting_test/./test.swf"  && self.snapshot.is_none() && false {
                                //     // Wait for the syscall-exit
                                //     child_proc.ptrace_syscall();
                                //     child_proc.wait_for();
                                //
                                //     // Update rax in the target to the new value (syscall return value)
                                //     if let Some(rax) = rax_overwrite {
                                //         unsafe { libc::ptrace(libc::PTRACE_POKEUSER, child, 8 * libc::RAX, rax) };
                                //         rax_overwrite = None;
                                //     }
                                //     // Skip processing the syscall exit because we will do it here
                                //     in_call = false;
                                //
                                //     // Single step the return back to the caller
                                //     unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, child, 0, 0) };
                                //     child_proc.wait_for();
                                //
                                //
                                //     //20k works
                                //     //10k works
                                //     //5k no works
                                //     //7.5k no works
                                //     //9k works
                                //     //8k close, no works
                                //     //8.5k no works
                                //     // for _ in 0..9000 - 25 {
                                //     //     unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, child, 0, 0) };
                                //     //     child_proc.wait_for();
                                //     // }
                                //
                                //     self.snapshot = Some(self.snapshot(child));
                                //
                                //     // Wait for next syscall
                                //     child_proc.ptrace_syscall();
                                //
                                //     continue;
                                // }
                            }
                            libc::SYS_read => {
                                // rdi => fd
                                // rsi => buf
                                // rdx => count

                                if self.vfs.has_fd(&rdi) {
                                    in_call = true;
                                    rax_overwrite = Some(0);

                                    // Copy the data from the fake file, to the buffer in the target
                                    for i in 0..rdx {
                                        if let Some(data) = self.vfs.read_u8(rdi) {
                                            unsafe { libc::ptrace(libc::PTRACE_POKEDATA, child, rsi + i, data as libc::c_uint) };
                                            rax_overwrite = Some(i + 1);
                                        } else {
                                            break;
                                        }
                                    }
                                    // println!("read(fd={}, buf={}, count={}) = {:?}", rdi, rsi, rdx, rax_overwrite);
                                }
                            }
                            libc::SYS_fcntl => {
                                if self.vfs.has_fd(&rdi) {
                                    in_call = true;
                                    assert_eq!(rsi, 1);
                                    rax_overwrite = Some(1);
                                }
                            }
                            libc::SYS_lseek => {
                                if self.vfs.has_fd(&rdi) {
                                    in_call = true;

                                    match rdx as i32 {
                                        libc::SEEK_SET => {
                                            self.vfs.set_pos(rdi, rsi).unwrap();
                                        },
                                        libc::SEEK_CUR => {
                                            self.vfs.set_pos(rdi, self.vfs.get_pos(rdi).unwrap() + rsi).unwrap();
                                        },
                                        libc::SEEK_END => {
                                            self.vfs.set_pos(rdi, self.vfs.get_len(rdi).unwrap() as i64).unwrap();
                                        }
                                        _ => panic!("We don't support other seek types {}", rdx)
                                    }

                                    rax_overwrite = Some(self.vfs.get_pos(rdi).unwrap() as i64);
                                    // println!("lseek(fd={}, pos={}, mode={})", rdi, rsi, rdx);
                                }
                            }
                            _ => {
                                // println!("Unhandled syscall {}", original_rax);
                            }
                        }
                    } else {
                        // println!("syscall originally returned: {}", rax);
                        // If we have decided to overwrite the return value given by the kernel
                        if let Some(new_rax) = rax_overwrite {
                            rax_overwrite = None;
                            // Update rax in the target to the new value
                            unsafe { libc::ptrace(libc::PTRACE_POKEUSER, child, 8 * libc::RAX, new_rax) };
                        }
                        in_call = false;
                    }

                    // Wait for next syscall
                    child_proc.ptrace_syscall();

                } else if stopsig == libc::SIGTRAP {
                    let event = status.0 >> 16;

                    if event == 0 {
                        #[cfg(breakpoints)]
                        {
                            //TODO: do we still need to check for 0xCC?
                            let instruction = unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, child, rip - 1, 0) };
                            let instruction_byte = (instruction & 0xFF) as u8;
                            // Check if the process stopped due to a breakpoint
                            if instruction_byte == 0xcc {
                                let breakpoint_relative_address = rip as usize - process_load_address - 1;
                                println!("breakpoint @ 0x{:x}", breakpoint_relative_address);

                                // Only restore instructions if the breakpoint was added by us, if the binary has an explicit int3 this will cause a loop when rip is reset to the start of the instruction
                                if let Some(bp) = self.breakpoints.get_mut(&breakpoint_relative_address) {
                                    bp.uninstall(child_proc);
                                    // Go back to the start of the original instruction so it actually gets executed
                                    unsafe { libc::ptrace(libc::PTRACE_POKEUSER, child, 8 * libc::RIP, rip - 1) };

                                    // Run the instruction that was overwritten with the breakpoint
                                    unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, child, 0, 0) };
                                    child_proc.wait_for();
                                    // unsafe { libc::wait(&mut status.0 as *mut _) };

                                    // Put the breakpoint back
                                    unsafe { libc::ptrace(libc::PTRACE_POKETEXT, child, process_load_address + breakpoint_relative_address, original_instruction) };

                                    match bp.action {
                                        BreakpointAction::SaveSnapshot => {
                                            if self.snapshot.is_none() {
                                                let sn = self.snapshot(child);
                                                self.snapshot = Some(sn);
                                            }
                                        }
                                        BreakpointAction::RestoreSnapshot => {
                                            //TODO: remove this hack

                                            // if String::from_utf8(self.vfs.get_file_content_by_path("/home/cub3d/.macromedia/Flash_Player/Logs/flashlog.txt").unwrap()).unwrap().contains("#CASE_") {
                                            let sn = self.snapshot.clone().expect("No snapshot to restore!");
                                            self.snapshot_restore(child, sn);
                                            // }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        #[cfg(feature = "child_processes")]
                        match event {
                            libc::PTRACE_EVENT_FORK => {
                                let pid = child_proc.ptrace_geteventmsg();
                                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACESYSGOOD)};
                                self.processes.insert(pid as i32, ());
                                println!("Child forked {}", pid);
                                Process(pid as i32).ptrace_syscall();
                            }
                            libc::PTRACE_EVENT_VFORK => {
                                let pid = child_proc.ptrace_geteventmsg();
                                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACESYSGOOD)};
                                self.processes.insert(pid as i32, ());
                                println!("Child vforked {}", pid);
                                Process(pid as i32).ptrace_syscall();
                            }
                            libc::PTRACE_EVENT_CLONE => {
                                let pid = child_proc.ptrace_geteventmsg();
                                unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACESYSGOOD)};
                                self.processes.insert(pid as i32, ());
                                println!("Child cloned {}", pid);
                                Process(pid as i32).ptrace_syscall();
                            }
                            libc::PTRACE_EVENT_EXIT => {
                                let exit_status = child_proc.ptrace_geteventmsg();
                                println!("child {:?} exit with status {}", pid, exit_status);
                                self.processes.remove(&pid.0);
                                // std::process::exit(0);
                            }
                            _ => panic!("Unknown ptrace event: {}", event)
                        }
                    }

                    child_proc.ptrace_syscall();

                } else {
                    #[cfg(feature = "child_processes")]
                    if unsafe{ libc::ptrace(libc::PTRACE_GETSIGINFO, child, 0, &mut si as *mut _)} < 0 {
                        println!("group stop");
                        child_proc.ptrace_syscall();
                    } else {
                        println!("signal stop @ 0x{:x}: {}", rip, stopsig);
                        child_proc.ptrace_syscall_signal(stopsig);
                    }
                    #[cfg(not(feature = "child_processes"))]
                    {
                        println!("signal stop @ 0x{:x}: {}", rip, stopsig);
                        child_proc.ptrace_syscall_signal(stopsig);
                    }
                }
            } else {
                println!("!wifstopped, target stopped, ending debug session");
                return;
            }
        }
    }

    #[cfg(breakpoints)]
    pub fn breakpoint(&mut self, addr: usize, action: BreakpointAction) {
        self.breakpoints.insert(addr, Breakpoint {
            original_byte: 0,
            action,
        });
    }
}
