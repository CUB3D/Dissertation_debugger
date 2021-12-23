use std::io::Cursor;
use std::time::Duration;
use crossbeam_channel::{Receiver, Sender};
use imgui::{im_str, Ui, Window};
use imgui::sys::igBeginMainMenuBar;
use imgui_filedialog::FileDialog;
use libc::stat;
use ptrace::{Breakpoint, Process};
use crate::debugger_ui::controls::WidgetControls;
use crate::debugger_ui::dissassemble::WidgetDisassemble;
use crate::debugger_ui::elf_info::WidgetElfInfo;
use crate::debugger_ui::stack::WidgetStack;
use crate::debugger_ui::syscall::WidgetSyscallList;
use crate::debugger_ui::widget::{UiMenu};
use crate::{debugger_ui, DebuggerMsg, DebuggingClient, elf, Msg, ui};
use crate::breakpoints::WidgetBreakpoints;
use crate::debugging_client::NativeDebuggingClient;
use crate::elf::Elf;
use crate::memory_map::WidgetMemoryMap;
use crate::registers::WidgetRegisters;

//TODO: move
#[derive(Default)]
pub struct DebuggerState {
    pub syscall_list: Vec<String>,
    pub breakpoints: Vec<Breakpoint>,
    pub process: Option<Process>,
    pub cache_user_regs: Option<Box<ptrace::UserRegs>>,
    pub elf: Option<Elf>,
    pub auto_stp: bool,
    pub single_step_mode: bool,
    pub started: bool,
    pub current_breakpoint: Option<Breakpoint>,
    //TODO: group these three together, if we have one we should have all
    pub sender: Option<Sender<Msg>>,
    pub reciever: Option<Receiver<DebuggerMsg>>,
    pub client: Option<NativeDebuggingClient>,
}

impl DebuggerState {
    pub fn load_binary(&mut self, binary: &str) {
        let mut binary_content = std::fs::read(&binary).expect("Failed to read binary");
        let elf_parsed = elf::parse(&mut Cursor::new(binary_content)).expect("Failed to parse elf");
        self.elf = Some(elf_parsed);

        self.client = Some(NativeDebuggingClient::default());
        let (sender,reciever) = self.client.as_mut().unwrap().start(&binary);
        self.sender = Some(sender);
        self.reciever = Some(reciever);
    }

    pub fn process_incoming_message(&mut self) {
        if let Ok(msg) = self.reciever.as_ref().unwrap().recv_timeout(Duration::from_nanos(1)) {
            match msg {
                DebuggerMsg::Trap { user_regs, fp_regs } => {
                    self.cache_user_regs = Some(user_regs);
                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::SyscallTrap { user_regs, fp_regs } => {
                    let proc = self.process.expect("Got syscalltrap without a process????????");

                    let syscall_desc = match user_regs.orig_ax as libc::c_long {
                        libc::SYS_brk => format!("brk({})", user_regs.di),
                        libc::SYS_arch_prctl => format!("SYS_arch_prctl({})", user_regs.di),
                        libc::SYS_mmap => format!("SYS_mmap(?)"),
                        libc::SYS_access => format!("SYS_access(?)"),
                        libc::SYS_newfstatat => format!("SYS_newfstatat(?)"),
                        libc::SYS_mprotect => format!("SYS_mprotect(?)"),
                        libc::SYS_write => format!("SYS_write(?)"),
                        libc::SYS_read => format!("SYS_read(?)"),
                        libc::SYS_munmap => format!("SYS_munmap(?)"),
                        libc::SYS_exit_group => format!("SYS_exit_group(?)"),
                        libc::SYS_pread64 => format!("SYS_pread64(?)"),

                        libc::SYS_close => {
                            format!("close({})", user_regs.di)
                        }
                        libc::SYS_openat => {
                            let fd_name = match user_regs.di as i32 {
                                -100 => "AT_FDCWD".to_string(),
                                _ => format!("{}", user_regs.di),
                            };

                            // let str_arg = if user_regs.si < 0x6FFFFFFFFFFF {
                            //     println!("Reading {:X}", user_regs.si);
                            //     unsafe { ptrace::ptrace_read_string(proc.0, user_regs.si as i64) }
                            // } else {
                            //     format!("0x{:X}", user_regs.si)
                            // };

                            let str_arg = format!("0x{:X}", user_regs.si);
                            format!("openat({}, {}, ?)", fd_name, str_arg)
                        }
                        _ => format!("Unknown({})", user_regs.orig_ax),
                    };

                    self.syscall_list.push(syscall_desc);
                    self.cache_user_regs = Some(user_regs);
                    if self.auto_stp {
                        self.sender.as_ref().unwrap().send(Msg::Continue);
                    }
                }
                DebuggerMsg::BPTrap { user_regs, fp_regs, breakpoint } => {
                    // int3 never auto continues
                    self.cache_user_regs = Some(user_regs);
                    self.current_breakpoint = Some(breakpoint);
                }
                DebuggerMsg::ProcessSpwn(p) => {
                    self.process = Some(p);
                }
            }
        }
    }

    /// Apply a message to the current state to transform it into the new state
    /// As long as this is always called on the local state for all sent messages and on the remote state
    /// for all recieved messages -> the two states will always remain in sync
    pub fn apply_state_transform(&mut self, msg: Msg) {
        match msg {
            Msg::Start => {}
            Msg::Continue => {}
            Msg::SingleStep(_) => {}
            Msg::AddBreakpoint(b) => self.breakpoints.push(b),
            Msg::RemoveBreakpoint(baddr) => {
                let index = self.breakpoints.iter_mut().position(|b| b.address == baddr).expect("Failed to find bp");
                self.breakpoints.remove(index);
            }
            Msg::InstallBreakpoint { .. } => {}
            Msg::DoSingleStep => {}
        }
    }

    /// Send a message to the debugging client, while ensuring that any transforms are applied to the local state
    pub fn send_msg(&mut self, msg: Msg) {
        self.apply_state_transform(msg.clone());
        self.sender.as_ref().unwrap().send(msg);
    }
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
    controls: WidgetControls,
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
            controls: Default::default(),
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
            self.controls.as_uimenu(),
        ];

        let fd = &mut self.fd;
        ui.main_menu_bar(|| {
            ui.menu(im_str!("File"), || {
                if ui.small_button(im_str!("Open")) {
                    fd.open_modal();
                }
            });
           ui.menu(im_str!("View"), || {
               for menu in &mut menus {
                   ui.checkbox(menu.title(), menu.visible_mut());
               }
           });
        });
        if fd.display() {
            println!("Browsing folder {:?}", fd.current_path());
            if fd.is_ok() {
                //TODO: no lossy string here
                state.load_binary(&fd.selection().unwrap().files().first().unwrap().to_string_lossy());
                println!("Open file {:?}", fd.selection().unwrap().files().first().unwrap())
            }
            fd.close();
        }

        for menu in menus {
            menu.render_if_visible(state, ui);
        }
    }
    pub fn init(mut debugger_state: DebuggerState) {
        let system = crate::ui::init("Debugger");
        let mut debugger_ui = debugger_ui::DebuggerUi::default();

        system.main_loop(move |_, ui| {
            if debugger_state.client.is_some() {
                debugger_state.process_incoming_message();
            }
            debugger_ui.render(ui, &mut debugger_state);
        });
    }
}


pub mod widget {
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

    use std::ffi::{CStr, CString};
    use imgui::sys::{igBeginTable, igEndTable, igTableHeadersRow, igTableNextColumn, igTableNextRow, igTableSetupColumn, ImGuiID, ImGuiTableColumnFlags, ImGuiTableFlags, ImVec2};
    use imgui::sys::cty::c_int;

    pub struct ImGuiTableBuilder;

    impl ImGuiTableBuilder {
        pub fn with_name<S: Fn(&mut Self), T: Fn(&mut Self)>(name: CString, column_count: c_int, setup_func: S, build_func: T) {
            if unsafe { igBeginTable(name.as_ptr(), column_count, ImGuiTableFlags::default(), ImVec2::zero(), 0.0f32) } {
                let mut s = Self{};
                setup_func(&mut s);
                unsafe { igTableHeadersRow(); }
                build_func(&mut s);
            }
            unsafe { igEndTable(); }
        }

        pub fn next_column(&mut self) {
            unsafe {
                igTableNextColumn();
            }
        }

        pub fn next_row(&mut self) {
            unsafe {
                igTableNextRow(0, 0f32);
            }
        }

        pub fn setup_column(&mut self, label: CString) {
            unsafe {
                igTableSetupColumn(label.as_ptr(), 0, 0f32, 0);
            }
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
                    imgui::im_str!($title)
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

pub mod stack {
    use std::io::{Read, Seek, SeekFrom};
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

                    let init = elf_parsed.by_name(".init");
                    let plt = elf_parsed.by_name(".plt");
                    let text = elf_parsed.by_name(".text");
                    let fini = elf_parsed.by_name(".fini");

                    let sections = [init, plt, text, fini].into_iter().filter(|f| f.is_some()).map(|f| f.unwrap()).collect::<Vec<_>>();

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
                                        state.sender.as_ref().unwrap().send(Msg::AddBreakpoint(bp));
                                    }
                                }

                                if let Some(token) = token {
                                    token.pop();
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

pub mod controls {
    use std::io::{Read, Seek, SeekFrom};
    use crate::debugger_ui::DebuggerState;
    use imgui::{im_str, ImStr, Ui, Window};
    use libc::stat;
    use ptrace::{MemoryMap, Process};
    use crate::debugger_ui::widget::{InnerRender, UiMenu};
    use crate::Msg;

    pub struct WidgetControls {
        pub visible: bool
    }
    define_ui_menu!(WidgetControls, "Controls");
    impl Default for WidgetControls {
        fn default() -> Self {
            Self {
                visible: true,
            }
        }
    }

    impl InnerRender for WidgetControls {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
            let mut send_continue = || {
                if let Some(bp) = state.current_breakpoint {
                    state.sender.as_ref().unwrap().send(Msg::DoSingleStep).expect("Failed to send msg");
                    state.sender.as_ref().unwrap().send(Msg::InstallBreakpoint { address: bp.address }).expect("Failed to send msg");
                    state.current_breakpoint = None;
                }
                state.sender.as_ref().unwrap().send(Msg::Continue).expect("Failed to send msg");
            };

            if ui.small_button(im_str!("|>")) {
                state.sender.as_ref().unwrap().send(Msg::Start).expect("Failed to send msg");
                state.started = true;
            }
            if state.started {
                if ui.checkbox(im_str!("Auto step"), &mut state.auto_stp) {
                    if state.auto_stp {
                        send_continue();
                    }
                }
                if !state.auto_stp {
                    if ui.small_button(im_str!("Step")) {
                        send_continue();
                    }
                }

                if ui.checkbox(im_str!("Single step mode"), &mut state.single_step_mode) {
                    state.sender.as_ref().unwrap()
                        .send(Msg::SingleStep(state.single_step_mode))
                        .expect("Failed to send msg");
                }
            }
        }
    }
}

//TODO: consider making render immutable and using events to do changes to state, so we can't forget to forward messages to the debug thread
