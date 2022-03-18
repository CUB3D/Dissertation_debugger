use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{TableColumnSetup, Ui, Window};

#[derive(Default)]
pub struct WidgetCallStack {
    pub visible: bool,
}
define_ui_menu!(WidgetCallStack, "Call Stack");

impl InnerRender for WidgetCallStack {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("CallStacks") {
            for state in &mut state.process_state {
                if let Some(tab) = ui.tab_item(format!("CallStacks ({})", state.process.0)) {
                    if let Some(table) = ui.begin_table_header(
                        "CallStack",
                        [
                            TableColumnSetup::new("Address"),
                            TableColumnSetup::new("Description"),
                        ],
                    ) {
                        if let Some(call_stack) = &state.call_stack {
                            for frame in &call_stack.0 {
                                ui.table_next_column();
                                ui.text(format!("{:#016X}", frame.addr));
                                ui.table_next_column();
                                ui.text(&frame.description);
                                ui.table_next_row();
                            }
                        } else {
                            ui.text("No call stack!");
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
