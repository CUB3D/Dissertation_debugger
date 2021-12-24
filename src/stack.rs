use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::debugger_ui::DebuggerState;
use crate::define_ui_menu;
use imgui::{ImStr, TableColumnSetup, Ui, Window};
use libc::stat;
use ptrace::{MemoryMap, Process};
use std::io::{Read, Seek, SeekFrom};

#[derive(Clone, Debug)]
pub struct CallStack(pub Vec<StackFrame>);
#[derive(Clone, Debug)]
pub struct StackFrame {
    pub addr: usize,
    pub description: String,
}

#[derive(Default)]
pub struct WidgetCallStack {
    pub visible: bool,
}
define_ui_menu!(WidgetCallStack, "Call Stack");

impl InnerRender for WidgetCallStack {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(_) = state.process {
            if let Some(call_stack) = &state.call_stack {
                if let Some(table) = ui.begin_table_header(
                    "Breakpoints",
                    [
                        TableColumnSetup::new("Address"),
                        TableColumnSetup::new("Description"),
                    ],
                ) {
                    for frame in &call_stack.0 {
                        ui.table_next_column();
                        ui.text(format!("{:#016X}", frame.addr));
                        ui.table_next_column();
                        ui.text(&frame.description);
                        ui.table_next_row();
                    }
                    table.end();
                }
            }
        } else {
            ui.text("No process!");
        }
    }
}
