use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use debugger_core::Msg;
use imgui::{TableColumnSetup, Ui, Window};

#[derive(Default)]
pub struct WidgetBreakpoints {
    pub visible: bool,
}
define_ui_menu!(WidgetBreakpoints, "Breakpoints");

impl InnerRender for WidgetBreakpoints {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(table) = ui.begin_table_header(
            "Breakpoints",
            [
                TableColumnSetup::new("Address"),
                TableColumnSetup::new("Type"),
            ],
        ) {
            for bp in state.breakpoints.clone().iter() {
                ui.table_next_column();
                ui.text(format!("{:X}", bp.address));
                ui.same_line();
                if ui.small_button("X") {
                    state.send_msg(Msg::RemoveBreakpoint(bp.address));
                }
                ui.table_next_column();
                ui.text("Enabled");
                ui.table_next_row();
            }
            table.end();
        }
    }
}
