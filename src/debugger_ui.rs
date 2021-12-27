use crate::breakpoints::WidgetBreakpoints;
#[cfg(target_os = "linux")]
use crate::memory_map::WidgetMemoryMap;
#[cfg(target_os = "linux")]
use crate::registers::WidgetRegisters;
use crate::stack::{WidgetCallStack};
use crate::{debugger_ui, DebuggerState};

use imgui::{Ui};
use imgui_filedialog::FileDialog;

use crate::controls::WidgetControls;
#[cfg(target_os = "linux")]
use crate::disassemble::WidgetDisassemble;
use crate::elf_info::WidgetElfInfo;
use crate::syscall::WidgetSyscallList;

pub struct DebuggerUi {
    fd: FileDialog,
    #[cfg(target_os = "linux")]
    mmap: WidgetMemoryMap,
    syscalls: WidgetSyscallList,
    #[cfg(target_os = "linux")]
    registers: WidgetRegisters,
    elf_info: WidgetElfInfo,
    breakpoints: WidgetBreakpoints,
    stack: WidgetCallStack,
    #[cfg(target_os = "linux")]
    dissassemble: WidgetDisassemble,
    controls: WidgetControls,
}

impl Default for DebuggerUi {
    fn default() -> Self {
        Self {
            fd: imgui_filedialog::FileDialog::create("Test"),
            #[cfg(target_os = "linux")]
            mmap: Default::default(),
            syscalls: Default::default(),
            #[cfg(target_os = "linux")]
            registers: Default::default(),
            elf_info: Default::default(),
            breakpoints: Default::default(),
            stack: Default::default(),
            #[cfg(target_os = "linux")]
            dissassemble: Default::default(),
            controls: Default::default(),
        }
    }
}

impl DebuggerUi {
    pub fn render(&mut self, ui: &Ui, state: &mut DebuggerState) {
        let mut menus = [
            #[cfg(target_os = "linux")]
            self.mmap.as_uimenu(),
            self.syscalls.as_uimenu(),
            #[cfg(target_os = "linux")]
            self.registers.as_uimenu(),
            self.elf_info.as_uimenu(),
            self.breakpoints.as_uimenu(),
            self.stack.as_uimenu(),
            #[cfg(target_os = "linux")]
            self.dissassemble.as_uimenu(),
            self.controls.as_uimenu(),
        ];

        let fd = &mut self.fd;
        ui.main_menu_bar(|| {
            ui.menu("File", || {
                if ui.small_button("Open") {
                    fd.open_modal();
                }
            });
            ui.menu("View", || {
                for menu in &mut menus {
                    ui.checkbox(menu.title(), menu.visible_mut());
                }
            });
        });
        if fd.display() {
            println!("Browsing folder {:?}", fd.current_path());
            if fd.is_ok() {
                //TODO: no lossy string here
                state.load_binary(
                    &fd.selection()
                        .unwrap()
                        .files()
                        .first()
                        .unwrap()
                        .to_string_lossy(),
                );
                println!(
                    "Open file {:?}",
                    fd.selection().unwrap().files().first().unwrap()
                )
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
    use crate::debugger_ui::DebuggerState;
    use imgui::{ImStr, Ui};

    pub trait UiMenu {
        fn render_if_visible(&mut self, state: &mut DebuggerState, ui: &Ui) {
            if *self.visible_mut() {
                self.render(state, ui);
            }
        }

        fn render(&mut self, state: &mut DebuggerState, ui: &Ui);
        fn visible_mut(&mut self) -> &mut bool;
        fn title(&self) -> &'static str;
    }

    pub trait InnerRender {
        fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui);
    }

    use imgui::sys::cty::c_int;
    use imgui::sys::{
        igBeginTable, igEndTable, igTableHeadersRow, igTableNextColumn, igTableNextRow,
        igTableSetupColumn, ImGuiTableFlags, ImVec2,
    };
    use std::ffi::CString;

    pub struct ImGuiTableBuilder;

    impl ImGuiTableBuilder {
        pub fn with_name<S: Fn(&mut Self), T: Fn(&mut Self)>(
            name: CString,
            column_count: c_int,
            setup_func: S,
            build_func: T,
        ) {
            if unsafe {
                igBeginTable(
                    name.as_ptr(),
                    column_count,
                    ImGuiTableFlags::default(),
                    ImVec2::zero(),
                    0.0f32,
                )
            } {
                let mut s = Self {};
                setup_func(&mut s);
                unsafe {
                    igTableHeadersRow();
                }
                build_func(&mut s);
            }
            unsafe {
                igEndTable();
            }
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

            fn title(&self) -> &'static str {
                $title
            }
        }
    };
}

//TODO: consider making render immutable and using events to do changes to state, so we can't forget to forward messages to the debug thread
