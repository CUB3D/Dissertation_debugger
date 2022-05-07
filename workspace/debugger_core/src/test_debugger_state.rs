use crossbeam_channel::bounded;
use linux_memory_map::{MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions, MemoryMapEntryPermissionsKind};
use crate::{Breakpoint, DebuggerMsg, DebuggerState, DebuggerStatus, Msg, Process, ProcessState, Syscall, SyscallArg};

#[test]
pub fn when_message_stop_is_sent_then_stop_should_be_received() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.sender = Some(sender);

    ds.send_msg(Msg::Stop);

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::Stop);
}

#[test]
pub fn when_message_restart_is_sent_then_restart_should_be_received() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.sender = Some(sender);

    ds.send_msg(Msg::Restart);

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::Restart);
}

#[test]
pub fn when_message_singlestep_is_sent_then_singlestep_should_be_received() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.sender = Some(sender);

    ds.send_msg(Msg::DoSingleStep);

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::DoSingleStep);
}

#[test]
pub fn when_message_stdin_is_sent_then_stdin_should_be_received() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.sender = Some(sender);

    ds.send_msg(Msg::StdinData("test".to_string()));

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::StdinData("test".to_string()));
}

#[test]
pub fn when_message_continue_is_sent_then_continue_should_be_received_and_status_should_be_running() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.status = DebuggerStatus::ReadyToStart;
    ds.sender = Some(sender);

    ds.send_msg(Msg::Continue);

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::Continue);

    assert_eq!(ds.status, DebuggerStatus::Running);
}

#[test]
pub fn when_message_addbreakpoint_is_sent_then_addbreakpoint_should_be_received_and_breakpoint_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.sender = Some(sender);

    ds.send_msg(Msg::AddBreakpoint(Breakpoint::new(1234)));

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::AddBreakpoint(Breakpoint::new(1234)));

    assert_eq!(ds.breakpoints, vec![Breakpoint::new(1234)]);
}

#[test]
pub fn when_message_removebreakpoint_is_sent_then_removebreakpoint_should_be_received_and_breakpoint_should_be_removed() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.sender = Some(sender);
    ds.breakpoints.push(Breakpoint::new(1234));

    ds.send_msg(Msg::RemoveBreakpoint(1234));

    let msg = reciever.recv().unwrap();
    assert_eq!(msg, Msg::RemoveBreakpoint(1234));

    assert_eq!(ds.breakpoints, vec![]);
}

#[test]
pub fn when_message_trap_recieved_then_status_should_be_updated() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.status = DebuggerStatus::Running;

    sender.send(DebuggerMsg::Trap);
    ds.process_incoming_message();

    assert_eq!(ds.status, DebuggerStatus::Paused);
}

#[test]
pub fn when_message_bptrap_recieved_then_status_should_be_updated_and_current_breakpoint_set() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.status = DebuggerStatus::Running;
    ds.current_breakpoint = None;

    sender.send(DebuggerMsg::BPTrap { breakpoint: Breakpoint::new(1234) });
    ds.process_incoming_message();

    assert_eq!(ds.status, DebuggerStatus::Breakpoint);
    assert_eq!(ds.current_breakpoint, Some(Breakpoint::new(1234)));
}

#[test]
pub fn when_message_childspawn_recieved_then_child_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);

    sender.send(DebuggerMsg::ChildProcessSpawn(Process(1234)));
    ds.process_incoming_message();

    assert_eq!(ds.process_state, vec![ProcessState::with_process(Process(1234))]);
}

#[test]
pub fn when_message_syscall_recieved_then_syscall_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    sender.send(DebuggerMsg::Syscall(Process(1234), Syscall {
        name: "test".to_string(),
        args: vec![SyscallArg::Address(0x1234)]
    }));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().syscall_list, vec![Syscall {
        name: "test".to_string(),
        args: vec![SyscallArg::Address(0x1234)]
    }]);
}

#[test]
pub fn when_message_mmap_recieved_then_mmap_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    sender.send(DebuggerMsg::MemoryMap(Process(1234), MemoryMap(vec![MemoryMapEntry {
        range: 0..1234,
        permissions: MemoryMapEntryPermissions {
            read: false,
            write: false,
            execute: false,
            kind: MemoryMapEntryPermissionsKind::Private
        },
        path: "/test".to_string(),
        offset: "1234".to_string(),
        dev: "asf".to_string(),
        inode: "5678".to_string()
    }])));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().memory_map, Some(MemoryMap(vec![MemoryMapEntry {
        range: 0..1234,
        permissions: MemoryMapEntryPermissions {
            read: false,
            write: false,
            execute: false,
            kind: MemoryMapEntryPermissionsKind::Private
        },
        path: "/test".to_string(),
        offset: "1234".to_string(),
        dev: "asf".to_string(),
        inode: "5678".to_string()
    }])));
}

/*
ProcessSpawn(Process),
    /// The given process has died with the given status
    ProcessDeath(Process, isize),
    /// The process has stopped, we have a new call stack to display
    CallStack(Process, CallStack),
    /// The given process has received new user registers
    UserRegisters(Process, Box<UserRegs>),
    /// The given process has received new floating point registers
    FpRegisters(Process, Box<FpRegs>),
    /// The given process has new memory state
    Memory(Process, Vec<(Vec<u8>, Range<usize>)>),
    /// The given process has new data in stderr
    StdErrContent(Process, Vec<u8>),
    /// The given process has new data in stdout
    StdOutContent(Process, Vec<u8>),
 */