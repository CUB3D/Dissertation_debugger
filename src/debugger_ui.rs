use imgui::{im_str, Ui, Window};
use imgui::sys::igBeginMainMenuBar;
use imgui_filedialog::FileDialog;
use libc::stat;
use ptrace::{Breakpoint, Process};
use crate::debugger_ui::breakpoints::WidgetBreakpoints;
use crate::debugger_ui::dissassemble::WidgetDisassemble;
use crate::debugger_ui::elf_info::WidgetElfInfo;
use crate::debugger_ui::mmap::WidgetMemoryMap;
use crate::debugger_ui::registers::WidgetRegisters;
use crate::debugger_ui::stack::WidgetStack;
use crate::debugger_ui::syscall::WidgetSyscallList;
use crate::debugger_ui::widget::{UiMenu};
use crate::elf::Elf;

//TODO: move
#[derive(Default, Clone)]
pub struct DebuggerState {
    pub syscall_list: Vec<String>,
    pub breakpoints: Vec<Breakpoint>,
    pub process: Option<Process>,
    pub cache_user_regs: Option<Box<ptrace::UserRegs>>,
    pub elf: Option<Elf>,
}

pub struct DebuggerUi {
    fd: FileDialog,
    mmap: WidgetMemoryMap,
    syscalls: WidgetSyscallList,
    registers: WidgetRegisters,
    elf_info: WidgetElfInfo,
    breakpoints: WidgetBreakpoints,
    stack: WidgetStack,
    dissassemble: WidgetDisassemble,
}

impl Default for DebuggerUi {
    fn default() -> Self {
        Self {
            fd: imgui_filedialog::FileDialog::create("Test"),
            mmap: Default::default(),
            syscalls: Default::default(),
            registers: Default::default(),
            elf_info: Default::default(),
            breakpoints: Default::default(),
            stack: Default::default(),
            dissassemble: Default::default(),
        }
    }
}

impl DebuggerUi {
    pub fn render(&mut self, ui: &Ui, state: &mut DebuggerState) {
        let mut menus = [
            self.mmap.as_uimenu(),
            self.syscalls.as_uimenu(),
            self.registers.as_uimenu(),
            self.elf_info.as_uimenu(),
            self.breakpoints.as_uimenu(),
            self.stack.as_uimenu(),
            self.dissassemble.as_uimenu(),
        ];

        let fd = &mut self.fd;
        ui.main_menu_bar(|| {
            ui.menu(im_str!("File"), true, || {
                if ui.small_button(im_str!("Open")) {
                    fd.open_modal();
                }
            });
           ui.menu(im_str!("View"), true, || {
               for menu in &mut menus {
                   ui.checkbox(menu.title(), menu.visible_mut());
               }
           });
        });
        if fd.display() {
            println!("Browsing folder {:?}", fd.current_path());
            if fd.is_ok() {
                println!("Open file {:?}", fd.selection().unwrap().files().first().unwrap())
            }
            fd.close();
        }
        Window::new(im_str!("Breakpoints")).build(ui, || {
            for (index, bp) in state.breakpoints.clone().iter().enumerate() {
                ui.text(im_str!("0x{:X}", bp.address));
                ui.same_line(50.);
                if ui.small_button(im_str!("X")) {
                    state.breakpoints.remove(index);
                }
            }
        });

        for menu in menus {
            menu.render_if_visible(state, ui);
        }
    }
}


mod widget {
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::DebuggerState;

    pub trait UiMenu {
        fn render_if_visible(&mut self, state: &mut DebuggerState, ui: &Ui) {
            if *self.visible_mut() {
                self.render(state, ui);
            }
        }

        fn render(&mut self, state: &mut DebuggerState, ui: &Ui);
        fn visible_mut(&mut self) -> &mut bool;
        fn title(&self) -> &'static ImStr;
    }

    pub trait InnerRender {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui);
    }
}

mod mmap {
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::DebuggerState;
    use crate::debugger_ui::widget::UiMenu;

    pub struct WidgetMemoryMap {
        pub visible: bool
    }

    impl WidgetMemoryMap {
        pub fn as_uimenu(&mut self) -> &mut dyn UiMenu {
            self
        }
    }

    impl Default for WidgetMemoryMap {
        fn default() -> Self {
            Self {
                visible: true
            }
        }
    }

    impl UiMenu for WidgetMemoryMap {
        fn render(&mut self, state: &mut DebuggerState, ui: &Ui) {
            Window::new(self.title()).build(ui, || {
                if let Some(proc) = state.process {
                    if let Some(mmap) = ptrace::get_memory_map(proc.0) {
                        for entry in mmap.0 {
                            ui.text(im_str!("{} 0x{:X}-0x{:X} {:?}", entry.path, entry.range.start, entry.range.end, entry.permissions));
                        }
                    } else {
                        ui.text(im_str!("Memory map not available"));
                    }
                } else {
                    ui.text(im_str!("Process not running!"));
                }
            });
        }

        fn visible_mut(&mut self) -> &mut bool {
            &mut self.visible
        }

        fn title(&self) -> &'static ImStr {
            im_str!("Memory Map")
        }
    }
}

mod syscall {
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::DebuggerState;
    use crate::debugger_ui::widget::UiMenu;

    pub struct WidgetSyscallList {
        pub visible: bool
    }

    impl WidgetSyscallList {
        pub fn as_uimenu(&mut self) -> &mut dyn UiMenu {
            self
        }
    }

    impl Default for WidgetSyscallList {
        fn default() -> Self {
            Self {
                visible: true
            }
        }
    }

    impl UiMenu for WidgetSyscallList {
        fn render(&mut self, state: &mut DebuggerState, ui: &Ui) {
            Window::new(self.title()).build(ui, || {
                for line in &state.syscall_list {
                    ui.text(im_str!("{}", line));
                }
            });
        }

        fn visible_mut(&mut self) -> &mut bool {
            &mut self.visible
        }

        fn title(&self) -> &'static ImStr {
            im_str!("Syscall History")
        }
    }
}

mod registers {
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::DebuggerState;
    use crate::debugger_ui::widget::UiMenu;

    pub struct WidgetRegisters {
        pub visible: bool
    }

    impl WidgetRegisters {
        pub fn as_uimenu(&mut self) -> &mut dyn UiMenu {
            self
        }
    }

    impl Default for WidgetRegisters {
        fn default() -> Self {
            Self {
                visible: true
            }
        }
    }

    impl UiMenu for WidgetRegisters {
        fn render(&mut self, state: &mut DebuggerState, ui: &Ui) {
            Window::new(self.title()).build(ui, || {
                if let Some(user_regs) = &state.cache_user_regs {
                    ui.text(im_str!("RAX: 0x{:X} ({})", user_regs.ax, user_regs.ax));
                    ui.text(im_str!("RBX: 0x{:X} ({})", user_regs.bx, user_regs.bx));
                    ui.text(im_str!("RCX: 0x{:X} ({})", user_regs.cx, user_regs.cx));
                    ui.text(im_str!("RDX: 0x{:X} ({})", user_regs.dx, user_regs.dx));
                    ui.text(im_str!("RBP: 0x{:X} ({})", user_regs.bp, user_regs.bp));
                    ui.text(im_str!("RSP: 0x{:X} ({})", user_regs.sp, user_regs.sp));
                    ui.text(im_str!("RSI: 0x{:X} ({})", user_regs.si, user_regs.si));
                    ui.text(im_str!("RDI: 0x{:X} ({})", user_regs.di, user_regs.di));
                    ui.new_line();

                    ui.text(im_str!("R8: 0x{:X} ({})", user_regs.r8, user_regs.r8));
                    ui.text(im_str!("R9: 0x{:X} ({})", user_regs.r9, user_regs.r9));
                    ui.text(im_str!("R10: 0x{:X} ({})", user_regs.r10, user_regs.r10));
                    ui.text(im_str!("R11: 0x{:X} ({})", user_regs.r11, user_regs.r11));
                    ui.text(im_str!("R12: 0x{:X} ({})", user_regs.r12, user_regs.r12));
                    ui.text(im_str!("R12: 0x{:X} ({})", user_regs.r13, user_regs.r13));
                    ui.text(im_str!("R14: 0x{:X} ({})", user_regs.r14, user_regs.r14));
                    ui.text(im_str!("R15: 0x{:X} ({})", user_regs.r15, user_regs.r15));
                    ui.new_line();

                    ui.text(im_str!("RIP: 0x{:X}", user_regs.ip));
                    ui.new_line();

                    ui.text(im_str!("RFLAGS: 0x{:X}", user_regs.flags));
                    ui.text(im_str!("CF: {}", (user_regs.flags & 0x0001) == 0x0001));
                    ui.text(im_str!("PF: {}", (user_regs.flags & 0x0004) == 0x0004));
                    ui.text(im_str!("AF: {}", (user_regs.flags & 0x0010) == 0x0010));
                    ui.text(im_str!("ZF: {}", (user_regs.flags & 0x0040) == 0x0040));
                    ui.text(im_str!("SF: {}", (user_regs.flags & 0x0080) == 0x0080));
                    ui.text(im_str!("TF: {}", (user_regs.flags & 0x0100) == 0x0100));
                    ui.text(im_str!("IF: {}", (user_regs.flags & 0x0200) == 0x0200));
                    ui.text(im_str!("DF: {}", (user_regs.flags & 0x0400) == 0x0400));
                    ui.text(im_str!("OF: {}", (user_regs.flags & 0x0800) == 0x0800));
                    ui.new_line();

                    ui.text(im_str!("GS: 0x{:X} ({})", user_regs.gs, user_regs.gs));
                    ui.text(im_str!("FS: 0x{:X} ({})", user_regs.fs, user_regs.fs));
                    ui.text(im_str!("ES: 0x{:X} ({})", user_regs.es, user_regs.es));
                    ui.text(im_str!("DS: 0x{:X} ({})", user_regs.ds, user_regs.ds));
                    ui.text(im_str!("CS: 0x{:X} ({})", user_regs.cs, user_regs.cs));
                    ui.text(im_str!("SS: 0x{:X} ({})", user_regs.ss, user_regs.ss));
                }
            });
        }

        fn visible_mut(&mut self) -> &mut bool {
            &mut self.visible
        }

        fn title(&self) -> &'static ImStr {
            im_str!("Registers")
        }
    }
}



    #[macro_export]
    macro_rules! define_ui_menu {
        ($name: ty, $title: expr) => {
            impl $name {
                pub fn as_uimenu(&mut self) -> &mut dyn UiMenu {
                    self
                }
            }

            impl UiMenu for $name {
                fn render(&mut self, state: &mut DebuggerState, ui: &Ui) {
                    Window::new(self.title()).build(ui, || {
                        self.render_inner(state, ui);
                    });
                }

                fn visible_mut(&mut self) -> &mut bool {
                    &mut self.visible
                }

                fn title(&self) -> &'static ImStr {
                    im_str!($title)
                }
            }
        };
    }

pub mod elf_info {
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::{DebuggerState};
    use crate::debugger_ui::widget::{InnerRender, UiMenu};

    #[derive(Default)]
    pub struct WidgetElfInfo {
        pub visible: bool
    }

    define_ui_menu!(WidgetElfInfo, "Info");

    impl InnerRender for WidgetElfInfo {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
            ui.text(im_str!("ELF:"));
            if let Some(elf_parsed) = &state.elf {
                ui.text(im_str!("Entry point: 0x{:X}", elf_parsed.entry_point));
                ui.text(im_str!("Section count: 0x{:X}", elf_parsed.sections.len()));

            } else {
                ui.text(im_str!("No binary loaded"));
            }

            ui.text("Process:");
            if let Some(p) = state.process {
                ui.text(im_str!("Process id: {}", p.0));
            } else {
                ui.text(im_str!("Process not started"));
            }
        }
    }
}

pub mod breakpoints {
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::{DebuggerState};
    use crate::debugger_ui::widget::{InnerRender, UiMenu};

    #[derive(Default)]
    pub struct WidgetBreakpoints {
        pub visible: bool
    }
    define_ui_menu!(WidgetBreakpoints, "Breakpoints");

    impl InnerRender for WidgetBreakpoints {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
            for (index, bp) in state.breakpoints.clone().iter().enumerate() {
                ui.text(im_str!("0x{:X}", bp.address));
                ui.same_line(50.);
                if ui.small_button(im_str!("X")) {
                    state.breakpoints.remove(index);
                }
            }
        }
    }
}

pub mod stack {
    use std::io::{Read, Seek, SeekFrom};
    use crate::debugger_ui::breakpoints::WidgetBreakpoints;
    use crate::debugger_ui::DebuggerState;
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::widget::{InnerRender, UiMenu};

    #[derive(Default)]
    pub struct WidgetStack {
        pub visible: bool
    }
    define_ui_menu!(WidgetStack, "Stack");

    impl InnerRender for WidgetStack {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
            if let Some(process) = state.process {
                if let Some(mmap) = ptrace::get_memory_map(process.0) {
                    let stack_section = mmap
                        .0
                        .iter()
                        .find(|m| m.path.contains("[stack]"))
                        .expect("Failed to find stack");
                    let mut mem_file =
                        std::fs::File::open(format!("/proc/{}/mem", process.0))
                            .expect("No mem?");
                    let mut mem =
                        vec![0u8; stack_section.range.end - stack_section.range.start];
                    mem_file
                        .seek(SeekFrom::Start(stack_section.range.start as u64))
                        .expect("Seek failed");
                    mem_file
                        .read_exact(&mut mem)
                        .expect("Failed to read memory range");

                    ui.columns(9, im_str!("mem"), true);
                    for (line_num, line) in mem.chunks(8).enumerate() {
                        ui.text(im_str!("{:X}", stack_section.range.start + line_num * 8));
                        ui.next_column();
                        for byte in line {
                            ui.text(im_str!("{:2X}", byte));
                            ui.next_column();
                        }
                    }
                }
            }
        }
    }
}

pub mod dissassemble {
    use std::collections::HashMap;
    use std::io::{Read, Seek, SeekFrom};
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult};
    use crate::debugger_ui::breakpoints::WidgetBreakpoints;
    use crate::debugger_ui::DebuggerState;
    use imgui::{im_str, ImStr, StyleColor, Ui, Window};
    use libc::stat;
    use ptrace::{Breakpoint, MemoryMap, Process};
    use crate::debugger_ui::widget::{InnerRender, UiMenu};
    use crate::{debugging_info, Msg};

    #[derive(Default, Clone)]
    struct MySymbolResolver {
        map: HashMap<u64, String>,
    }

    impl SymbolResolver for MySymbolResolver {
        fn symbol(
            &mut self, _instruction: &Instruction, _operand: u32, _instruction_operand: Option<u32>,
            address: u64, _address_size: u32,
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
        pub visible: bool
    }
    define_ui_menu!(WidgetDisassemble, "Dissassemble");

    impl InnerRender for WidgetDisassemble {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
            let load_address = 0x555555554000;



            if let Some(elf_parsed) = &state.elf {
                let subprograms = debugging_info::parse_dwarf_info(&elf_parsed).subprograms;
                let mut resolver = Box::new(MySymbolResolver::default());
                for prog in &subprograms {
                    resolver.map.insert(prog.start_addr + load_address, prog.name.clone());
                }

                if let Some(user_regs) = &state.cache_user_regs {
                    // The address that the process is loaded into memory at
                    let base_address = load_address + elf_parsed.entry_point;
                    //TODO: just use memory directly, no elf parse+handle self modifing
                    //TODO: ip should be ip of instruction 0

                    let init = elf_parsed.by_name(".init").expect("Failed to get .init");
                    let plt = elf_parsed.by_name(".plt").expect("Failed to get .plt");
                    let text = elf_parsed.by_name(".text").expect("Failed to get .text");
                    let fini = elf_parsed.by_name(".fini").expect("Failed to get .fini");

                    let sections = [init, plt, text, fini];

                    for text in &sections {
                        ui.text(im_str!("{}:", text.name));
                        let mut decoder = Decoder::with_ip(
                            64,
                            &text.data,
                            load_address + text.addr,
                            DecoderOptions::NONE,
                        );
                        let mut instruction = Instruction::default();
                        let mut formatter = IntelFormatter::with_options(Some(resolver.clone()), None);
                        let mut output = String::new();

                        for ii in 0..0x8000 {
                            if decoder.can_decode() {
                                decoder.decode_out(&mut instruction);

                                output.clear();
                                formatter.format(&instruction, &mut output);

                                if let Some(sub) = subprograms.iter().find(|s| s.start_addr == (instruction.ip() - load_address)) {
                                    ui.text(im_str!("<{}>: ", sub.name))
                                }


                                let token = if instruction.ip() == user_regs.ip {
                                    let token = ui.push_style_color(StyleColor::Text, [0.0, 1.0, 0.0, 1.0]);
                                    // ui.text_colored(
                                    //     [0.0, 1.0, 0.0, 1.0],
                                    //     im_str!("{:016X} {}", instruction.ip(), output),
                                    // );
                                    ui.set_scroll_here_y();
                                    Some(token)
                                } else {
                                    None
                                };

                                let bp = state.breakpoints.iter().find(|bp| bp.address == instruction.ip() as usize);
                                let bp_text = if bp.is_some() {
                                    "B "
                                } else {
                                    "  "
                                };

                                if ui.small_button(&im_str!("{}{:016X} {}", bp_text, instruction.ip(), output)) {
                                    if let Some(pos) = state.breakpoints.iter().position(|bp| bp.address == instruction.ip() as usize) {
                                        state.breakpoints.remove(pos);
                                    } else {
                                        let bp = Breakpoint::new(instruction.ip() as usize);
                                        state.breakpoints.push(bp);
                                        // sender.send(Msg::AddBreakpoint(bp));
                                    }
                                }

                                if let Some(token) = token {
                                    token.pop(ui);
                                }
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

//TODO: consider making render immutable and using events to do changes to state, so we can't forget to forward messages to the debug thread
