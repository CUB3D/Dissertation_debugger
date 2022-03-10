use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui_memory_editor::MemoryEditor;

use imgui::{TableColumnSetup, Ui, Window};

use std::ffi::CString;
use std::ops::Range;
use std::os::linux::raw::stat;
use debugger_core::ProcessState;

#[derive(Default)]
pub struct WidgetMemoryView {
    pub visible: bool,
}
define_ui_menu!(WidgetMemoryView, "Memory");

impl InnerRender for WidgetMemoryView {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("MemoryMaps") {
            for state in &mut state.process_state {
                if let Some(tab) = ui.tab_item(format!("Memory ({})", state.process.0)) {
                    if let Some(table) = ui.begin_table_header(
                        "Mem",
                        [
                            TableColumnSetup::new("Address"),
                            TableColumnSetup::new("Hex"),
                            TableColumnSetup::new("ASCII"),
                        ],
                    ) {
                        let mut hit_first_visisble = false;
                        let mut hit_last_visisble = false;
                        'memory_sections: for (mem, mem_range) in &state.memory {
                            for (i, c) in mem.chunks(16).enumerate() {
                                ui.table_next_column();

                                if hit_last_visisble {
                                    ui.table_next_row();
                                    continue;
                                }

                                ui.text(&format!("{:#016X}:", mem_range.start + 16 * i)[2..]);

                                if !ui.is_item_visible() {
                                    ui.table_next_row();

                                    // If we have already hit the first visible line, this is the last visible line, so skip to end
                                    if hit_first_visisble {
                                        hit_last_visisble = true;
                                    }

                                    continue;
                                } else {
                                    // If we havn't hit the first visible line yet, track that we just hit it
                                    if !hit_first_visisble {
                                        hit_first_visisble = true;
                                    }
                                }

                                ui.table_next_column();

                                for c in c {
                                    ui.text(format!("{:02X}", c));
                                    ui.same_line();
                                }
                                ui.table_next_column();
                                for c in c {
                                    if let Some(s) = std::char::from_u32(*c as u32) {
                                        if s.is_ascii_alphanumeric() || s.is_ascii_punctuation() || s.is_ascii_whitespace() {
                                            ui.text(s.to_string());
                                        } else {
                                            ui.text(".");
                                        }
                                    } else {
                                        ui.text(".");
                                    }
                                    ui.same_line();
                                }

                                ui.table_next_row();
                            }
                        }

                        table.end();
                    }
                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}
