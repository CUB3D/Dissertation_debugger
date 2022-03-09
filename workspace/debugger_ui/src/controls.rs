use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{Ui, Window};
use debugger_core::Msg;

pub struct WidgetControls {
    pub visible: bool,
}
define_ui_menu!(WidgetControls, "Controls");
impl Default for WidgetControls {
    fn default() -> Self {
        Self { visible: true }
    }
}

impl WidgetControls {
    fn send_continue(&self, state: &mut DebuggerState) {
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
        state.halt_reason = "".to_string();
    }
}

impl InnerRender for WidgetControls {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {

        // Show start button only if a file is loaded
        if state.elf.is_some() || true {
            if state.process.is_some() {
                // Restart button, only shown when a process is currently running
                if ui.small_button("Restart") {
                    state
                        .sender
                        .as_ref()
                        .unwrap()
                        .send(Msg::Restart)
                        .expect("Failed to send msg");
                }
            } else {
                // Start button, only shown when no process is currently running
                if ui.small_button("|>") {
                    state
                        .sender
                        .as_ref()
                        .unwrap()
                        .send(Msg::Start)
                        .expect("Failed to send msg");
                    state.started = true;
                }
            }
        }

        if state.process.is_some() {
            // Stop button, only shown when a process is currently running
            if ui.small_button("Stop") {
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Msg::Stop)
                    .expect("Failed to send msg");
                state.started = false;
            }
        }

        ui.text(format!("Halt reason: {}", &state.halt_reason));

        if state.started {
            if ui.checkbox("Auto step", &mut state.auto_step) {
                if state.auto_step {
                    self.send_continue(state);
                }
            }
            if !state.auto_step {
                if ui.small_button("Step") {
                    self.send_continue(state);
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
