use imgui::Ui;
use debugger_core::{DebuggerState, Msg};
use crate::debugger_ui::widget::InnerRender;
use crate::define_ui_menu;
use crate::debugger_ui::widget::UiMenu;
use imgui::Window;

#[derive(Default)]
pub struct WidgetConsole {
    pub visible: bool,
    pub stdin_data: String,
}
define_ui_menu!(WidgetConsole, "Output");

impl InnerRender for WidgetConsole {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("Console") {
            for pstate in &state.process_state {
                if let Some(tab) = ui.tab_item(format!("Console ({})", pstate.process.0)) {


                    if let Some(tab_bar) = ui.tab_bar(format!("stderr {}", pstate.process.0)) {
                        if let Some(tab) = ui.tab_item("Stderr") {
                            ui.text(&pstate.stderr);
                            tab.end();
                        }
                        if let Some(tab) = ui.tab_item("Stdout") {
                            ui.text(&pstate.stdout);
                            tab.end();
                        }
                        if let Some(tab) = ui.tab_item("Stdin") {
                            ui.input_text("Input", &mut self.stdin_data)
                                .build();
                            if ui.small_button("Send") {
                                state
                                    .sender
                                    .as_ref()
                                    .unwrap()
                                    .send(Msg::StdinData(self.stdin_data.clone()))
                                    .expect("Failed to send msg");
                                self.stdin_data.clear();
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