use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{Ui, Window};
use debugger_core::Msg;
use debugger_core::debugger_state::DebuggerStatus;

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
        if state.elf.is_none() {
            ui.text("Open a binary with `File > open` to begin");
            return;
        }

        if state.status == DebuggerStatus::Running || state.status == DebuggerStatus::Dead {
            // Restart button, only shown when a process is currently running
            if ui.small_button("Restart") {
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Msg::Restart)
                    .expect("Failed to send msg");
            }
        }
        if state.status == DebuggerStatus::Running {
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

        //Continue button, only shown when paused on a breakpoint or waiting to start
        if state.status == DebuggerStatus::ReadyToStart ||  state.status == DebuggerStatus::Breakpoint || state.status == DebuggerStatus::Paused {
            if ui.small_button("Continue") {
                state.send_msg(Msg::Start);
            }

            //TODO: this wont work if you click this first instead of continue
            if ui.small_button("Single Step") {
                state.send_msg(Msg::DoSingleStep);
            }
        }

        //ui.text(format!("Halt reason: {}", &state.halt_reason));

        /*if state.started {
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
        }*/
    }
}
