use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use debugger_core::debugger_state::DebuggerStatus;
use debugger_core::Msg;
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
        if state.elf.is_none() {
            ui.text("Open a binary with `File > open` to begin");
            return;
        }

        if state.status == DebuggerStatus::Running
            || state.status == DebuggerStatus::Dead
            || state.status == DebuggerStatus::Breakpoint
        {
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
        if state.status == DebuggerStatus::Running || state.status == DebuggerStatus::Breakpoint {
            // Stop button, only shown when a process is currently running
            if ui.small_button("Stop") {
                state
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(Msg::Stop)
                    .expect("Failed to send msg");
            }
        }

        //Continue button, only shown when paused on a breakpoint or waiting to start
        if state.status == DebuggerStatus::ReadyToStart
            || state.status == DebuggerStatus::Breakpoint
            || state.status == DebuggerStatus::Paused
        {
            if ui.small_button("Continue") {
                state.send_msg(Msg::Continue);
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
