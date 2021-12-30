use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{Ui, Window};


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

#[derive(Default)]
pub struct WidgetSyscallList {
    pub visible: bool,
}
define_ui_menu!(WidgetSyscallList, "Syscalls");

impl InnerRender for WidgetSyscallList {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        for state in &state.process_state {
            for syscall in &state.syscall_list {
                ui.text(&syscall.name);
                ui.same_line();
                ui.text("(");
                ui.same_line();
                for (index, arg) in syscall.args.iter().enumerate() {
                    match arg {
                        SyscallArg::U64(x) => ui.text(format!("{}", x)),
                        SyscallArg::FileDescriptor(fd) => ui.text(format!("{}", fd)),
                        SyscallArg::ProcessId(pid) => ui.text(format!("{}", pid)),
                        SyscallArg::FilePath(path) => {
                            if let Some(file_name) = std::path::Path::new(path).file_name() {
                                ui.text(format!("\"{}\"", file_name.to_string_lossy()))
                            } else {
                                ui.text(format!("\"{}\"", path))
                            }
                        }
                        SyscallArg::Address(a) => ui.text(format!("{:X}", a)),
                        SyscallArg::String(s) => ui.text(format!("\"{}\"", s)),
                    }
                    ui.same_line();
                    if index != syscall.args.len() - 1 {
                        ui.text(",");
                        ui.same_line();
                    }
                }
                ui.text(")");
            }
        }
    }
}
