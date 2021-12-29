use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState, Msg};
use imgui::{Ui, Window};

pub struct WidgetControls {
    pub visible: bool,
}
define_ui_menu!(WidgetControls, "Controls");
impl Default for WidgetControls {
    fn default() -> Self {
        Self { visible: true }
    }
}

impl InnerRender for WidgetControls {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        let mut send_continue = || {
            if let Some(bp) = &state.current_breakpoint {
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Msg::DoSingleStep)
                    .expect("Failed to send msg");
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Msg::InstallBreakpoint {
                        address: bp.address,
                    })
                    .expect("Failed to send msg");
                state.current_breakpoint = None;
            }
            state
                .sender
                .as_ref()
                .unwrap()
                .send(Msg::Continue)
                .expect("Failed to send msg");
        };

        if ui.small_button("|>") {
            state
                .sender
                .as_ref()
                .unwrap()
                .send(Msg::Start)
                .expect("Failed to send msg");
            state.started = true;
        }
        if state.started {
            if ui.checkbox("Auto step", &mut state.auto_stp) {
                if state.auto_stp {
                    send_continue();
                }
            }
            if !state.auto_stp {
                if ui.small_button("Step") {
                    send_continue();
                }
            }

            if ui.checkbox("Single step mode", &mut state.single_step_mode) {
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Msg::SingleStep(state.single_step_mode))
                    .expect("Failed to send msg");
            }
        }
    }
}
