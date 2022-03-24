//! Widget for displaying X86 register state
use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{define_ui_menu, DebuggerState};
use imgui::{TableColumnFlags, TableColumnSetup, TableFlags, Ui, Window};

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

                    // Bit of a hack, last font is monospace
                    let ft = ui.push_font(ui.fonts().fonts().last().unwrap().clone());


                    #[cfg(target_arch = "aarch64")]
                    if let Some(user_regs) = &state.cache_user_regs {

                        ui.text(format!("PC: 0x{:X} ({})", user_regs.pc, user_regs.pc));
                        ui.text(format!("SP: 0x{:X} ({})", user_regs.sp, user_regs.sp));

                        for (index, reg) in user_regs.regs.iter().copied().enumerate() {
                            let maybe_ascii = if let Some(s) = std::char::from_u32(reg as u32) {
                                if s.is_ascii_alphanumeric()
                                    || s.is_ascii_punctuation()
                                    || s.is_ascii_whitespace() {
                                    format!(" ({})", s)
                                } else {
                                    "".to_string()
                                }
                            } else {
                                "".to_string()
                            };

                            ui.text(format!("x{}: 0x{:X} ({}){}", index, reg, reg, maybe_ascii));
                        }
                    }

                    #[cfg(target_arch = "x86_64")]
                    if let Some(user_regs) = &state.cache_user_regs {
                        // Instruction pointer
                        ui.text(format!("RIP: {:016X}", user_regs.ip));

                        // Flags table
                        let mut headers = [
                            TableColumnSetup::new("CF"),
                            TableColumnSetup::new("PF"),
                            TableColumnSetup::new("AF"),
                            TableColumnSetup::new("ZF"),
                            TableColumnSetup::new("SF"),
                            TableColumnSetup::new("TF"),
                            TableColumnSetup::new("IF"),
                            TableColumnSetup::new("DF"),
                            TableColumnSetup::new("OF"),

                            TableColumnSetup::new("IOPL"),
                            TableColumnSetup::new("NT"),
                            TableColumnSetup::new("RF"),
                            TableColumnSetup::new("VM"),
                            TableColumnSetup::new("AC"),
                            TableColumnSetup::new("VIF"),
                            TableColumnSetup::new("VIP"),
                            TableColumnSetup::new("ID"),
                        ];
                        for h in &mut headers {
                            h.flags = TableColumnFlags::NO_RESIZE;
                        }
                        if let Some(table) = ui.begin_table_header(
                            "Reg-Flags",
                            headers,
                        ) {
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 0)) == (1 << 0)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 2)) == (1 << 2)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 4)) == (1 << 4)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 6)) == (1 << 6)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 7)) == (1 << 7)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 8)) == (1 << 8)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 9)) == (1 << 9)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 10)) == (1 << 10)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 11)) == (1 << 11)) as u8));
                            ui.table_next_column();
                            // IOPL
                            ui.text(format!("{}{}", ((user_regs.flags & (1 << 13)) == (1 << 13)) as u8, ((user_regs.flags & (1 << 12)) == (1 << 12)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 14)) == (1 << 14)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 16)) == (1 << 16)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 17)) == (1 << 17)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 18)) == (1 << 18)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 19)) == (1 << 19)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 20)) == (1 << 20)) as u8));
                            ui.table_next_column();
                            ui.text(format!("{}", ((user_regs.flags & (1 << 21)) == (1 << 21)) as u8));

                            table.end();
                        }

                        // General registers
                        if let Some(t) = ui.begin_table_with_flags("Reg-User", 4, TableFlags::BORDERS_INNER_V) {
                            ui.table_next_column();
                            ui.text(format!("RAX: {:016X}", user_regs.ax));
                            ui.table_next_column();
                            ui.text(format!("RBX: {:016X}", user_regs.bx));
                            ui.table_next_column();
                            ui.text(format!("RCX: {:016X}", user_regs.cx));
                            ui.table_next_column();
                            ui.text(format!("RDX: {:016X}", user_regs.dx));

                            ui.table_next_column();
                            ui.text(format!("RSI: {:016X}", user_regs.si));
                            ui.table_next_column();
                            ui.text(format!("RDI: {:016X}", user_regs.di));
                            ui.table_next_column();
                            ui.text(format!("RBP: {:016X}", user_regs.bp));
                            ui.table_next_column();
                            ui.text(format!("RSP: {:016X}", user_regs.sp));

                            // Extended 64 bit registers
                            ui.table_next_column();
                            ui.text(format!("R8 : {:016X}", user_regs.r8));
                            ui.table_next_column();
                            ui.text(format!("R9 : {:016X}", user_regs.r9));
                            ui.table_next_column();
                            ui.text(format!("R10: {:016X}", user_regs.r10));
                            ui.table_next_column();
                            ui.text(format!("R11: {:016X}", user_regs.r11));

                            ui.table_next_column();
                            ui.text(format!("R12: {:016X}", user_regs.r12));
                            ui.table_next_column();
                            ui.text(format!("R12: {:016X}", user_regs.r13));
                            ui.table_next_column();
                            ui.text(format!("R14: {:016X}", user_regs.r14));
                            ui.table_next_column();
                            ui.text(format!("R15: {:016X}", user_regs.r15));

                            t.end();
                        }

                        // Segment registers
                        if let Some(t) = ui.begin_table_with_flags("Reg-Segment", 6, TableFlags::BORDERS_INNER_V) {
                            ui.table_next_column();
                            ui.text(format!("GS: {:04X}", user_regs.gs));
                            ui.table_next_column();
                            ui.text(format!("FS: {:04X}", user_regs.fs));
                            ui.table_next_column();
                            ui.text(format!("ES: {:04X}", user_regs.es));
                            ui.table_next_column();
                            ui.text(format!("DS: {:04X}", user_regs.ds));
                            ui.table_next_column();
                            ui.text(format!("CS: {:04X}", user_regs.cs));
                            ui.table_next_column();
                            ui.text(format!("SS: {:04X}", user_regs.ss));

                            t.end();
                        }
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
                                "XMM{}: {:08X}{:08X}-{:08X}{:08X}",
                                index, ymm_reg[0], ymm_reg[1], ymm_reg[2], ymm_reg[3]
                            ));
                        }
                        ui.new_line();

                        // AVX-256 YMM registers
                        for (index, ymm_reg) in fp_regs.xmm_space.chunks(8).enumerate() {
                            ui.text(format!(
                                "YMM{}: {:08X}{:08X}-{:08X}{:08X}-{:08X}{:08X}-{:08X}{:08X}",
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

                    ft.end();

                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}
