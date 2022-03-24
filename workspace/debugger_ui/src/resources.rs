use imgui::{TableColumnSetup, Ui};
use debugger_core::DebuggerState;
use crate::debugger_ui::widget::InnerRender;
use crate::define_ui_menu;
use crate::debugger_ui::widget::UiMenu;
use imgui::Window;

#[derive(Default)]
pub struct WidgetResources {
    pub visible: bool,
}
define_ui_menu!(WidgetResources, "Resources");

impl InnerRender for WidgetResources {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("Resources") {
            for state in &state.process_state {
                if let Some(tab) = ui.tab_item(format!("Resources ({})", state.process.0)) {


                    ui.text("Open files:");
                    if let Some(table) = ui.begin_table_header(
                        format!("Files ({})", state.process.0),
                        [
                            TableColumnSetup::new("#"),
                            TableColumnSetup::new("Name"),
                        ],
                    ) {

                        ui.table_next_column();
                        ui.text("5");
                        ui.table_next_column();
                        ui.text("Test.txt");

                        table.end();
                    }

                    ui.text("Open sockets:");
                    if let Some(table) = ui.begin_table_header(
                        format!("Sockets ({})", state.process.0),
                        [
                            TableColumnSetup::new("#"),
                            TableColumnSetup::new("Type"),
                            TableColumnSetup::new("Protocol"),
                            TableColumnSetup::new("Dest"),
                        ],
                    ) {

                        ui.table_next_column();
                        ui.text("15");
                        ui.table_next_column();
                        ui.text("AF_INET");
                        ui.table_next_column();
                        ui.text("SOCK_STREAM");
                        ui.table_next_column();
                        ui.text("74.125.235.20:8080");

                        table.end();
                    }


                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}