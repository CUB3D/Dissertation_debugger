use imgui::{im_str, ImStr, Ui, Window};
use imgui::sys::igBeginTable;
use libc::stat;
use ptrace::{MemoryMap, Process};
use crate::debugger_ui::DebuggerState;
use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::define_ui_menu;

#[derive(Default)]
pub struct WidgetMemoryMap {
    pub visible: bool
}
define_ui_menu!(WidgetMemoryMap, "Memory Map");

impl InnerRender for WidgetMemoryMap {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(proc) = state.process {
            if let Some(mmap) = ptrace::get_memory_map(proc.0) {
                for entry in mmap.0 {
                    ui.text(im_str!("{} 0x{:X}-0x{:X} {:?}", entry.path, entry.range.start, entry.range.end, entry.permissions));
                }
            } else {
                ui.text(im_str!("Memory map not available"));
            }
        } else {
            ui.text(im_str!("Process not running!"));
        }
    }
}
