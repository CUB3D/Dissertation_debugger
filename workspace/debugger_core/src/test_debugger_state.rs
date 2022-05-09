use crossbeam_channel::bounded;
use linux_memory_map::{MemoryMap, MemoryMapEntry, MemoryMapEntryPermissions, MemoryMapEntryPermissionsKind};
use crate::{Breakpoint, CallStack, DebuggerMsg, DebuggerState, DebuggerStatus, FpRegs, Msg, Process, ProcessState, StackFrame, Syscall, SyscallArg, UserRegs};

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

#[test]
pub fn when_message_stdout_recieved_then_content_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    sender.send(DebuggerMsg::StdOutContent(Process(1234), "Test\n".to_string().into_bytes()));
    ds.process_incoming_message();
    sender.send(DebuggerMsg::StdOutContent(Process(1234), "Test\n".to_string().into_bytes()));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().stdout, "Test\nTest\n".to_string());
}

#[test]
pub fn when_message_stderr_recieved_then_content_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    sender.send(DebuggerMsg::StdErrContent(Process(1234), "Test\n".to_string().into_bytes()));
    ds.process_incoming_message();
    sender.send(DebuggerMsg::StdErrContent(Process(1234), "Test\n".to_string().into_bytes()));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().stderr, "Test\nTest\n".to_string());
}

#[test]
pub fn when_message_userregs_recieved_then_content_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    let mut user_regs = unsafe { Box::<UserRegs>::new_zeroed().assume_init() };
    #[cfg(target_arch = "aarch64")]
        {
            user_regs.pc = 0x12345;
        }
    #[cfg(target_arch = "x86_64")]
        {
            user_regs.ip = 0x12345;
        }

    sender.send(DebuggerMsg::UserRegisters(Process(1234), user_regs.clone()));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().cache_user_regs, Some(user_regs));
}

#[test]
pub fn when_message_fpregs_recieved_then_content_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    let mut fp_regs = unsafe { Box::<FpRegs>::new_zeroed().assume_init() };
    fp_regs.ftw = 0x1234;

    sender.send(DebuggerMsg::FpRegisters(Process(1234), fp_regs.clone()));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().cache_fp_regs, Some(fp_regs));
}

#[test]
pub fn when_message_callstack_recieved_then_content_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    let cs = CallStack(vec![StackFrame {
        addr: 0x12345,
        description: "Test123".to_string()
    }]);

    sender.send(DebuggerMsg::CallStack(Process(1234), cs.clone()));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().call_stack, Some(cs));
}

#[test]
pub fn when_message_memory_recieved_then_content_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);
    ds.process_state.push(ProcessState::with_process(Process(1234)));

    let mem = vec![(vec![1, 2, 3, 4], 0..4)];

    sender.send(DebuggerMsg::Memory(Process(1234), mem.clone()));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().memory, mem);
}

#[test]
pub fn when_message_spawn_recieved_then_process_should_be_added() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);

    sender.send(DebuggerMsg::ProcessSpawn(Process(1234)));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap(), &ProcessState::with_process(Process(1234)));
}

#[test]
pub fn when_message_death_of_first_proc_recieved_then_process_should_be_removed_and_status_dead() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);

    sender.send(DebuggerMsg::ProcessSpawn(Process(1234)));
    ds.process_incoming_message();
    sender.send(DebuggerMsg::ProcessDeath(Process(1234), 0));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap().alive, false);
    assert_eq!(ds.status, DebuggerStatus::Dead);
}

#[test]
pub fn when_message_death_of_other_proc_recieved_then_process_should_be_removed_and_status_not_dead() {
    let (sender, reciever) = bounded(1);

    let mut ds = DebuggerState::default();
    ds.reciever = Some(reciever);

    sender.send(DebuggerMsg::ProcessSpawn(Process(1234)));
    ds.process_incoming_message();
    sender.send(DebuggerMsg::ChildProcessSpawn(Process(5678)));
    ds.process_incoming_message();
    sender.send(DebuggerMsg::ProcessDeath(Process(5678), 0));
    ds.process_incoming_message();

    assert_eq!(ds.process_state.first().unwrap(), &ProcessState::with_process(Process(1234)));
    assert_eq!(ds.process_state.iter().nth(1).unwrap().alive, false);
    assert_ne!(ds.status, DebuggerStatus::Dead);
}
