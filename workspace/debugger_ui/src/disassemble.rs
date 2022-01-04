use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{debugging_info, define_ui_menu, DebuggerState};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult,
};
use imgui::{StyleColor, Ui, Window};

use debugger_core::common_binary_file::BinaryFile;
use std::collections::HashMap;
use debugger_core::Breakpoint;
use debugger_core::Msg;

#[derive(Default, Clone)]
struct MySymbolResolver {
    map: HashMap<u64, String>,
}

impl SymbolResolver for MySymbolResolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult> {
        if let Some(symbol_string) = self.map.get(&address) {
            // The 'address' arg is the address of the symbol and doesn't have to be identical
            // to the 'address' arg passed to symbol(). If it's different from the input
            // address, the formatter will add +N or -N, eg. '[rax+symbol+123]'
            Some(SymbolResult::with_str(address, symbol_string.as_str()))
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct WidgetDisassemble {
    pub visible: bool,
}
define_ui_menu!(WidgetDisassemble, "Disassemble");

impl InnerRender for WidgetDisassemble {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        //TODO: get this from mmap?
        let load_address = 0x555555554000;

        if let Some(elf_parsed) = &state.elf {
            if let BinaryFile::Elf(elf_parsed) = elf_parsed {
                let subprograms = debugging_info::parse_dwarf_info(&elf_parsed).subprograms;
                let mut resolver = Box::new(MySymbolResolver::default());
                for prog in &subprograms {
                    resolver
                        .map
                        .insert(prog.start_addr + load_address, prog.name.clone());
                }

                if let Some(user_regs) = &state.process_state.first().unwrap().cache_user_regs {
                    // The address that the process is loaded into memory at
                    let _base_address = load_address + elf_parsed.entry_point;
                    //TODO: just use memory directly, no elf parse+handle self modifing
                    //TODO: ip should be ip of instruction 0

                    let init = elf_parsed.by_name(".init");
                    let plt = elf_parsed.by_name(".plt");
                    let text = elf_parsed.by_name(".text");
                    let fini = elf_parsed.by_name(".fini");

                    let sections = [init, plt, text, fini]
                        .into_iter()
                        .filter(|f| f.is_some())
                        .map(|f| f.unwrap())
                        .collect::<Vec<_>>();

                    for text in &sections {
                        ui.text(format!("{}:", text.name));
                        let mut decoder = Decoder::with_ip(
                            64,
                            &text.data,
                            load_address + text.addr,
                            DecoderOptions::NONE,
                        );
                        let mut instruction = Instruction::default();
                        let mut formatter =
                            IntelFormatter::with_options(Some(resolver.clone()), None);
                        let mut output = String::new();

                        for _ii in 0..0x8000 {
                            if decoder.can_decode() {
                                decoder.decode_out(&mut instruction);

                                output.clear();
                                formatter.format(&instruction, &mut output);

                                if let Some(sub) = subprograms
                                    .iter()
                                    .find(|s| s.start_addr == (instruction.ip() - load_address))
                                {
                                    ui.text(format!("<{}>: ", sub.name))
                                }

                                let token = if instruction.ip() == user_regs.ip {
                                    let token =
                                        ui.push_style_color(StyleColor::Text, [0.0, 1.0, 0.0, 1.0]);
                                    // ui.text_colored(
                                    //     [0.0, 1.0, 0.0, 1.0],
                                    //     im_str!("{:016X} {}", instruction.ip(), output),
                                    // );
                                    ui.set_scroll_here_y();
                                    Some(token)
                                } else {
                                    None
                                };

                                let bp = state
                                    .breakpoints
                                    .iter()
                                    .find(|bp| bp.address == instruction.ip() as usize);
                                let bp_text = if bp.is_some() { "B " } else { "  " };

                                if ui.small_button(&format!(
                                    "{}{:016X} {}",
                                    bp_text,
                                    instruction.ip(),
                                    output
                                )) {
                                    if let Some(pos) = state
                                        .breakpoints
                                        .iter()
                                        .position(|bp| bp.address == instruction.ip() as usize)
                                    {
                                        state.breakpoints.remove(pos);
                                    } else {
                                        let bp = Breakpoint::new(instruction.ip() as usize);
                                        state.breakpoints.push(bp);
                                        state.sender.as_ref().unwrap().send(Msg::AddBreakpoint(bp));
                                    }
                                }

                                // {
                                //     if instruction.is_call_near() {
                                //         let b64 = instruction.near_branch64();
                                //         println!("b64 = {:X}", b64);
                                //
                                //         let current_pos = ui.cursor_pos();
                                //         let draw_list = ui.get_window_draw_list();
                                //         const WHITE: [f32; 3] = [1.0, 1.0, 1.0];
                                //         draw_list
                                //             .add_line(
                                //                 [current_pos[0], current_pos[1]],
                                //                 [current_pos[0] - 100., current_pos[1] - 100.],
                                //                 WHITE,
                                //             )
                                //             .build();
                                //     }
                                // }

                                if let Some(token) = token {
                                    token.pop();
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
