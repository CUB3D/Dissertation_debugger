use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui_memory_editor::MemoryEditor;

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

                        if !ui.is_item_visible() {
                            ui.table_next_row();
                            continue;
                        }

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

        // for state in &state.process_state {
        //     let mut memory_editor = MemoryEditor::<ProcessState>::new()
        //     .read_only(true)
        //     .mem_size(state.memory.iter().map(|(m, _)| m.len()).sum());
        //     .read_fn(|mem, offset| {
        //         for chunk in mem

        //         mem.read(offset)
        //     });
        // }


    }
}
