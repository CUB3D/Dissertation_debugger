use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};

use imgui::{Ui, Window};

#[derive(Default)]
pub struct WidgetElfInfo {
    pub visible: bool,
}
define_ui_menu!(WidgetElfInfo, "Info");

impl InnerRender for WidgetElfInfo {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        ui.text("ELF:");
        if let Some(elf_parsed) = &state.elf {
            ui.text(format!("Entry point: {:X}", elf_parsed.entry_point()));
            ui.text(format!("Section count: {:X}", elf_parsed.section_count()));
        } else {
            ui.text("No binary loaded");
        }

        ui.text(format!("{}", std::process::id()));
    }
}
