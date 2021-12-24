use crate::debugger_ui::widget::{ImGuiTableBuilder, InnerRender, UiMenu};
use crate::debugger_ui::DebuggerState;
use crate::define_ui_menu;
use imgui::sys::{
    igBeginTable, igEndTable, igNextColumn, igTableNextColumn, igText, ImGuiTableFlags, ImVec2,
};
use imgui::{ImStr, Ui, Window};
use libc::stat;
use ptrace::{MemoryMap, Process};
use std::ffi::CString;

#[derive(Default)]
pub struct WidgetMemoryMap {
    pub visible: bool,
}
define_ui_menu!(WidgetMemoryMap, "Memory Map");

impl InnerRender for WidgetMemoryMap {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(proc) = state.process {
            if let Some(mmap) = ptrace::get_memory_map(proc.0) {
                ImGuiTableBuilder::with_name(
                    CString::new("mmap").unwrap(),
                    5,
                    |s| {
                        s.setup_column(CString::new("Address").unwrap());
                        s.setup_column(CString::new("Size").unwrap());
                        s.setup_column(CString::new("Comment").unwrap());
                        s.setup_column(CString::new("Type").unwrap());
                        s.setup_column(CString::new("Permissions").unwrap());
                        s.next_column();
                    },
                    |b| {
                        for entry in &mmap.0 {
                            b.next_column();
                            ui.text(format!("{:X}", entry.range.start));
                            b.next_column();
                            ui.text(format!("{:X}", entry.range.len()));
                            b.next_column();
                            ui.text(format!("{}", entry.path));
                            b.next_column();
                            ui.text(format!("{}", entry.permissions.kind));
                            b.next_column();
                            ui.text(format!(
                                "{}{}{}",
                                if entry.permissions.read { "R" } else { "-" },
                                if entry.permissions.write { "W" } else { "-" },
                                if entry.permissions.execute { "X" } else { "-" }
                            ));
                            b.next_row();
                        }
                    },
                );
            } else {
                ui.text("Memory map not available");
            }
        } else {
            ui.text("Process not running!");
        }
    }
}

//Ideas for this module, track initial perms to see if they change, show sub-sections like .text and types
