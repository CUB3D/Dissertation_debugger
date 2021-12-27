use crate::debugger_ui::widget::{InnerRender, UiMenu};
use imgui::{Ui, Window};
use crate::{DebuggerState, define_ui_menu};

#[derive(Default)]
pub struct WidgetElfInfo {
    pub visible: bool,
}
define_ui_menu!(WidgetElfInfo, "Info");

impl InnerRender for WidgetElfInfo {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        ui.text("ELF:");
        if let Some(elf_parsed) = &state.elf {
            ui.text(format!("Entry point: 0x{:X}", elf_parsed.entry_point));
            ui.text(format!("Section count: 0x{:X}", elf_parsed.sections.len()));
        } else {
            ui.text("No binary loaded");
        }

        ui.text("Process:");
        if let Some(p) = state.process {
            ui.text(format!("Process id: {}", p.0));
        } else {
            ui.text("Process not started");
        }
    }
}