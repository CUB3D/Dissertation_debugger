use imgui::{im_str, Ui, Window};
use imgui::sys::igBeginMainMenuBar;
use imgui_filedialog::FileDialog;
use libc::stat;
use ptrace::{Breakpoint, Process};
use crate::debugger_ui::breakpoints::WidgetBreakpoints;
use crate::debugger_ui::elf_info::WidgetElfInfo;
use crate::debugger_ui::mmap::WidgetMemoryMap;
use crate::debugger_ui::registers::WidgetRegisters;
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
}

impl Default for DebuggerUi {
    fn default() -> Self {
        Self {
            fd: imgui_filedialog::FileDialog::create("Test"),
            mmap: Default::default(),
            syscalls: Default::default(),
            registers: Default::default(),
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

//TODO: consider making render immutable and using events to do changes to state, so we can't forget to forward messages to the debug thread
