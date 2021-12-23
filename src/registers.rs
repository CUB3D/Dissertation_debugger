use imgui::{im_str, ImStr, Ui, Window};
use libc::stat;
use ptrace::{MemoryMap, Process};
use crate::debugger_ui::DebuggerState;
use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::define_ui_menu;

pub struct WidgetRegisters {
    pub visible: bool
}
define_ui_menu!(WidgetRegisters, "Registers");

impl Default for WidgetRegisters {
    fn default() -> Self {
        Self {
            visible: true
        }
    }
}

impl InnerRender for WidgetRegisters {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        Window::new(self.title()).build(ui, || {
            if let Some(user_regs) = &state.cache_user_regs {
                ui.text(format!("RAX: 0x{:X} ({})", user_regs.ax, user_regs.ax));
                ui.text(format!("RBX: 0x{:X} ({})", user_regs.bx, user_regs.bx));
                ui.text(format!("RCX: 0x{:X} ({})", user_regs.cx, user_regs.cx));
                ui.text(format!("RDX: 0x{:X} ({})", user_regs.dx, user_regs.dx));
                ui.text(format!("RBP: 0x{:X} ({})", user_regs.bp, user_regs.bp));
                ui.text(format!("RSP: 0x{:X} ({})", user_regs.sp, user_regs.sp));
                ui.text(format!("RSI: 0x{:X} ({})", user_regs.si, user_regs.si));
                ui.text(format!("RDI: 0x{:X} ({})", user_regs.di, user_regs.di));
                ui.new_line();

                ui.text(format!("R8: 0x{:X} ({})", user_regs.r8, user_regs.r8));
                ui.text(format!("R9: 0x{:X} ({})", user_regs.r9, user_regs.r9));
                ui.text(format!("R10: 0x{:X} ({})", user_regs.r10, user_regs.r10));
                ui.text(format!("R11: 0x{:X} ({})", user_regs.r11, user_regs.r11));
                ui.text(format!("R12: 0x{:X} ({})", user_regs.r12, user_regs.r12));
                ui.text(format!("R12: 0x{:X} ({})", user_regs.r13, user_regs.r13));
                ui.text(format!("R14: 0x{:X} ({})", user_regs.r14, user_regs.r14));
                ui.text(format!("R15: 0x{:X} ({})", user_regs.r15, user_regs.r15));
                ui.new_line();

                ui.text(format!("RIP: 0x{:X}", user_regs.ip));
                ui.new_line();

                ui.text(format!("RFLAGS: 0x{:X}", user_regs.flags));
                ui.text(format!("CF: {}", (user_regs.flags & 0x0001) == 0x0001));
                ui.text(format!("PF: {}", (user_regs.flags & 0x0004) == 0x0004));
                ui.text(format!("AF: {}", (user_regs.flags & 0x0010) == 0x0010));
                ui.text(format!("ZF: {}", (user_regs.flags & 0x0040) == 0x0040));
                ui.text(format!("SF: {}", (user_regs.flags & 0x0080) == 0x0080));
                ui.text(format!("TF: {}", (user_regs.flags & 0x0100) == 0x0100));
                ui.text(format!("IF: {}", (user_regs.flags & 0x0200) == 0x0200));
                ui.text(format!("DF: {}", (user_regs.flags & 0x0400) == 0x0400));
                ui.text(format!("OF: {}", (user_regs.flags & 0x0800) == 0x0800));
                ui.new_line();

                ui.text(format!("GS: 0x{:X} ({})", user_regs.gs, user_regs.gs));
                ui.text(format!("FS: 0x{:X} ({})", user_regs.fs, user_regs.fs));
                ui.text(format!("ES: 0x{:X} ({})", user_regs.es, user_regs.es));
                ui.text(format!("DS: 0x{:X} ({})", user_regs.ds, user_regs.ds));
                ui.text(format!("CS: 0x{:X} ({})", user_regs.cs, user_regs.cs));
                ui.text(format!("SS: 0x{:X} ({})", user_regs.ss, user_regs.ss));
            }
        });
    }
}
