use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};

use imgui::{TabBarFlags, TableColumnSetup, Ui, Window};

use std::ffi::CString;
use std::ops::Range;

#[derive(Default)]
pub struct WidgetMemoryMap {
    pub visible: bool,
}
define_ui_menu!(WidgetMemoryMap, "Memory Map");

impl InnerRender for WidgetMemoryMap {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("MemoryMaps") {
            for state in &state.process_state {
                if let Some(tab) = ui.tab_item(format!("Memory Map ({})", state.process.0)) {
                    if let Some(mmap) = &state.memory_map {
                        if let Some(table) = ui.begin_table_header(
                            "Mem",
                            [
                                TableColumnSetup::new("Address"),
                                TableColumnSetup::new("Size"),
                                TableColumnSetup::new("Comment"),
                                TableColumnSetup::new("Type"),
                                TableColumnSetup::new("Permissions"),
                            ],
                        ) {
                            for entry in &mmap.0 {
                                ui.table_next_column();
                                ui.text(format!("{:X}", entry.range.start));
                                ui.table_next_column();
                                ui.text(format!("{:X}", entry.range.len()));
                                ui.table_next_column();
                                ui.text(format!("{}", entry.path));
                                ui.table_next_column();
                                ui.text(format!("{}", entry.permissions.kind));
                                ui.table_next_column();
                                ui.text(format!(
                                    "{}{}{}",
                                    if entry.permissions.read { "R" } else { "-" },
                                    if entry.permissions.write { "W" } else { "-" },
                                    if entry.permissions.execute { "X" } else { "-" }
                                ));
                                ui.table_next_row();
                            }
                            table.end();
                        }
                    } else {
                        ui.text("Memory map not available");
                    }

                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}

//Ideas for this module, track initial perms to see if they change, show sub-sections like .text and types
