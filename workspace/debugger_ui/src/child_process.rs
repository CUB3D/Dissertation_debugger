use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{TableColumnSetup, Ui, Window};

#[derive(Default)]
pub struct WidgetChildProcesses {
    pub visible: bool,
}
define_ui_menu!(WidgetChildProcesses, "Children");

impl InnerRender for WidgetChildProcesses {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(table) = ui.begin_table_header(
            "Children",
            [TableColumnSetup::new("#"), TableColumnSetup::new("ID")],
        ) {
            for (ii, child) in state.process_state.iter().enumerate() {
                ui.table_next_column();
                ui.text(format!("{}", ii));
                ui.table_next_column();
                ui.text(format!("{}", child.process.0));
                ui.table_next_row();
            }
            table.end();
        }
    }
}
