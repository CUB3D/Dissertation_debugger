use crate::debugger_ui::widget::{InnerRender, UiMenu};
use imgui::{Ui, Window};
use crate::{DebuggerState, define_ui_menu};

#[derive(Default)]
pub struct WidgetSyscallList {
    pub visible: bool,
}
define_ui_menu!(WidgetSyscallList, "Syscalls");

impl InnerRender for WidgetSyscallList {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        for line in &state.syscall_list {
            ui.text(line);
        }
    }
}
