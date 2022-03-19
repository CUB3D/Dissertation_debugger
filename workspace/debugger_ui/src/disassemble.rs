use crate::debugger_ui::widget::{InnerRender, UiMenu};
use crate::{debugging_info, define_ui_menu, DebuggerState};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult,
};
use imgui::{StyleColor, Ui, Window};

use crate::debugging_info::SubProgram;
use debugger_core::common_binary_file::BinaryFile;
use debugger_core::Breakpoint;
use debugger_core::Msg;
use std::collections::HashMap;

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

        if let Some(elf_bin) = &state.elf {
            if let BinaryFile::Elf(elf_buffer) = elf_bin {
                let elf_parsed = goblin::elf::Elf::parse(&elf_buffer).unwrap();

                let subprograms: Vec<SubProgram> =
                    debugging_info::parse_dwarf_info(&elf_buffer, &elf_parsed).subprograms;
                let mut resolver = Box::new(MySymbolResolver::default());
                for prog in &subprograms {
                    resolver
                        .map
                        .insert(prog.start_addr + load_address, prog.name.clone());
                }

                // The address that the process is loaded into memory at
                let _base_address = load_address + elf_parsed.header.e_entry;
                //TODO: just use memory directly, no elf parse+handle self modifing
                //TODO: ip should be ip of instruction 0

                let mut section_names = Vec::new();
                for s in elf_parsed.section_headers {
                    if let Some(name) = elf_parsed.shdr_strtab.get_at(s.sh_name) {
                        section_names.push((s.sh_addr, name.to_string()));
                    }
                }

                let mut sections = Vec::new();
                for section in elf_parsed.program_headers {
                    // We only want to dissassemble exec sections
                    if !section.is_executable() {
                        continue;
                    }

                    let data_size = section.p_memsz.max(section.p_filesz) as usize;
                    let mut section_data = vec![0u8; data_size];

                    // Fill in the filesize bytes with the contents of the file, the rest will be left set to 0
                    section_data[..section.p_filesz as usize].copy_from_slice(
                        elf_buffer
                            .get(
                                (section.p_offset as usize)
                                    ..(section.p_offset as usize + section.p_filesz as usize),
                            )
                            .unwrap(),
                    );

                    //TODO: get name
                    sections.push((
                        section.p_vaddr,
                        section_data,
                        format!("{:X}", section.p_vaddr),
                    ));
                }

                for (virt_addr, section_data, name) in &sections {
                    let mut decoder = Decoder::with_ip(
                        64,
                        section_data,
                        load_address + virt_addr,
                        DecoderOptions::NONE,
                    );
                    // decoder.set
                    let mut instruction = Instruction::default();
                    let mut formatter = IntelFormatter::with_options(Some(resolver.clone()), None);
                    let mut output = String::new();

                    while decoder.can_decode() {
                        decoder.decode_out(&mut instruction);

                        if let Some((_, name)) = section_names
                            .iter()
                            .find(|(addr, _)| *addr == instruction.ip() - load_address)
                        {
                            ui.text(format!("{}:", name));
                        }

                        output.clear();
                        formatter.format(&instruction, &mut output);

                        if let Some(sub) = subprograms
                            .iter()
                            .find(|s| s.start_addr == (instruction.ip() - load_address))
                        {
                            ui.text(format!("<{}>: ", sub.name))
                        }

                        // If one process ip points here
                        let token = if state
                            .process_state
                            .iter()
                            .find(|p| {
                                p.cache_user_regs
                                    .as_ref()
                                    .map(|ur| ur.ip == instruction.ip())
                                    .unwrap_or(false)
                            })
                            .is_some()
                        {
                            let token = ui.push_style_color(StyleColor::Text, [0.0, 1.0, 0.0, 1.0]);
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
                                state
                                    .sender
                                    .as_ref()
                                    .unwrap()
                                    .send(Msg::RemoveBreakpoint(instruction.ip() as usize));
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
                        }
                    }
                }
            }
        }
    }
}
