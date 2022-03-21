//! Widget for displaying X86 register state
use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{Ui, Window};

pub struct WidgetRegisters {
    pub visible: bool,
}
define_ui_menu!(WidgetRegisters, "Registers");

impl Default for WidgetRegisters {
    fn default() -> Self {
        Self { visible: true }
    }
}

impl InnerRender for WidgetRegisters {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("Registers") {
            for state in &mut state.process_state {
                if let Some(tab) = ui.tab_item(format!("Registers ({})", state.process.0)) {
                    #[cfg(target_arch = "aarch64")]
                    if let Some(user_regs) = &state.cache_user_regs {
                        ui.text(format!("PC: 0x{:X} ({})", user_regs.pc, user_regs.pc));
                        ui.text(format!("SP: 0x{:X} ({})", user_regs.sp, user_regs.sp));

                        for (index, reg) in user_regs.regs.iter().copied().enumerate() {
                            ui.text(format!("x{}: 0x{:X} ({})", index, reg, reg));
                        }
                    }
                    #[cfg(target_arch = "x86_64")]
                    if let Some(user_regs) = &state.cache_user_regs {
                        // General registers
                        ui.text(format!("RAX: 0x{:X} ({})", user_regs.ax, user_regs.ax));
                        ui.text(format!("RBX: 0x{:X} ({})", user_regs.bx, user_regs.bx));
                        ui.text(format!("RCX: 0x{:X} ({})", user_regs.cx, user_regs.cx));
                        ui.text(format!("RDX: 0x{:X} ({})", user_regs.dx, user_regs.dx));
                        ui.text(format!("RBP: 0x{:X} ({})", user_regs.bp, user_regs.bp));
                        ui.text(format!("RSP: 0x{:X} ({})", user_regs.sp, user_regs.sp));
                        ui.text(format!("RSI: 0x{:X} ({})", user_regs.si, user_regs.si));
                        ui.text(format!("RDI: 0x{:X} ({})", user_regs.di, user_regs.di));
                        ui.new_line();

                        // Extended 64 bit registers
                        ui.text(format!("R8: 0x{:X} ({})", user_regs.r8, user_regs.r8));
                        ui.text(format!("R9: 0x{:X} ({})", user_regs.r9, user_regs.r9));
                        ui.text(format!("R10: 0x{:X} ({})", user_regs.r10, user_regs.r10));
                        ui.text(format!("R11: 0x{:X} ({})", user_regs.r11, user_regs.r11));
                        ui.text(format!("R12: 0x{:X} ({})", user_regs.r12, user_regs.r12));
                        ui.text(format!("R12: 0x{:X} ({})", user_regs.r13, user_regs.r13));
                        ui.text(format!("R14: 0x{:X} ({})", user_regs.r14, user_regs.r14));
                        ui.text(format!("R15: 0x{:X} ({})", user_regs.r15, user_regs.r15));
                        ui.new_line();

                        // Instruction pointer
                        ui.text(format!("RIP: 0x{:X}", user_regs.ip));
                        ui.new_line();

                        // Flags
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

                        // Segment registers
                        ui.text(format!("GS: 0x{:X} ({})", user_regs.gs, user_regs.gs));
                        ui.text(format!("FS: 0x{:X} ({})", user_regs.fs, user_regs.fs));
                        ui.text(format!("ES: 0x{:X} ({})", user_regs.es, user_regs.es));
                        ui.text(format!("DS: 0x{:X} ({})", user_regs.ds, user_regs.ds));
                        ui.text(format!("CS: 0x{:X} ({})", user_regs.cs, user_regs.cs));
                        ui.text(format!("SS: 0x{:X} ({})", user_regs.ss, user_regs.ss));
                        ui.new_line();
                    }

                    if let Some(fp_regs) = &state.cache_fp_regs {
                        // X87 / XMM / floating point register stack
                        for (index, st_reg) in fp_regs.st_space.chunks(4).enumerate() {
                            ui.text(format!(
                                "ST({}): {:08X}{:08X}{:04X}",
                                index,
                                st_reg[0],
                                st_reg[1],
                                (st_reg[2] & 0xFFFF_0000) as u16
                            ));
                        }
                        ui.new_line();

                        // X87 Tag Word
                        ui.text(format!("x87 Tag Word: {:X}", fp_regs.ftw));
                        for ii in 0..8 {
                            let shift = ii * 2;
                            let v = fp_regs.ftw & (0b11 << shift) >> shift;

                            let desc = match v {
                                0b00 => "valid",
                                0b01 => "zero",
                                0b10 => "special",
                                0b11 => "Empty",
                                _ => "Unknown",
                            };

                            ui.text(format!("x87TW_{}: {} ({})", ii, v, desc));
                        }

                        //TODO: x87 status word + control word + mxcsr

                        // AVX-128 XMM registers
                        for (index, ymm_reg) in fp_regs.xmm_space.chunks(8).enumerate() {
                            ui.text(format!(
                                "XMM{}: {:08X}{:08X}{:08X}{:08X}",
                                index, ymm_reg[0], ymm_reg[1], ymm_reg[2], ymm_reg[3]
                            ));
                        }
                        ui.new_line();

                        // AVX-256 YMM registers
                        for (index, ymm_reg) in fp_regs.xmm_space.chunks(8).enumerate() {
                            ui.text(format!(
                                "YMM{}: {:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
                                index,
                                ymm_reg[0],
                                ymm_reg[1],
                                ymm_reg[2],
                                ymm_reg[3],
                                ymm_reg[4],
                                ymm_reg[5],
                                ymm_reg[6],
                                ymm_reg[7]
                            ));
                        }
                        ui.new_line();
                    }

                    if state.cache_user_regs.is_none() && state.cache_fp_regs.is_none() {
                        ui.text("No registers available yet!");
                    }

                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}
