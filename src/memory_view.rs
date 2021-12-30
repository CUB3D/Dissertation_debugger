use crate::debugger_ui::widget::{ImGuiTableBuilder, InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};

use imgui::{TableColumnSetup, Ui, Window};

use std::ffi::CString;
use std::ops::Range;

#[derive(Default)]
pub struct WidgetMemoryView {
    pub visible: bool,
}
define_ui_menu!(WidgetMemoryView, "Memory");

impl InnerRender for WidgetMemoryView {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(table) = ui.begin_table_header(
            "Mem",
            [
                TableColumnSetup::new("Address"),
                TableColumnSetup::new("Hex"),
                TableColumnSetup::new("ASCII"),
            ],
        ) {
            for state in &state.process_state {
                for (mem, mem_range) in &state.memory {
                    for (i, c) in mem.chunks(16).enumerate() {
                        ui.table_next_column();
                        ui.text(format!("{:#016X}", mem_range.start + 16 * i));
                        ui.table_next_column();

                        for c in c {
                            ui.text(format!("{:02X}", c));
                            ui.same_line();
                        }
                        ui.table_next_column();
                        for c in c {
                            if let Ok(s) = std::str::from_utf8(&[*c]) {
                                ui.text(s);
                            } else {
                                ui.text(".");
                            }
                            ui.same_line();
                        }

                        ui.table_next_row();
                    }
                }
            }

            table.end();
        }


    }
}
