use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use debugger_core::SyscallArg;
use imgui::{Ui, Window};

#[derive(Default)]
pub struct WidgetSyscallList {
    pub visible: bool,
}
define_ui_menu!(WidgetSyscallList, "Syscalls");

impl InnerRender for WidgetSyscallList {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("SyscallHistory") {
            for state in &state.process_state {
                if let Some(tab) = ui.tab_item(format!("Syscall History ({})", state.process.0)) {
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
                                    if let Some(file_name) = std::path::Path::new(path).file_name()
                                    {
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

                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}
