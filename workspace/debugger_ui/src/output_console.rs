use imgui::Ui;
use debugger_core::DebuggerState;
use crate::debugger_ui::widget::InnerRender;
use crate::define_ui_menu;
use crate::debugger_ui::widget::UiMenu;
use imgui::Window;

#[derive(Default)]
pub struct WidgetConsole {
    pub visible: bool,
}
define_ui_menu!(WidgetConsole, "Output");

impl InnerRender for WidgetConsole {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("Console") {
            for state in &state.process_state {
                if let Some(tab) = ui.tab_item(format!("Console ({})", state.process.0)) {


                    if let Some(tab_bar) = ui.tab_bar(format!("stderr {}", state.process.0)) {
                        if let Some(tab) = ui.tab_item("Stderr") {

                            for line in &state.stderr {
                                ui.text(line);
                            }

                            tab.end();
                        }
                        tab_bar.end();
                    }


                        tab.end();
                }
            }
            tab_bar.end();
        }
    }
}