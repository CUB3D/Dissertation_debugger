use imgui::{TableColumnSetup, Ui};
use debugger_core::DebuggerState;
use crate::debugger_ui::widget::InnerRender;
use crate::define_ui_menu;
use crate::debugger_ui::widget::UiMenu;
use imgui::Window;
use linux_fd_info::FdLink;

#[derive(Default)]
pub struct WidgetResources {
    pub visible: bool,
}
define_ui_menu!(WidgetResources, "Resources");

impl InnerRender for WidgetResources {
    fn render_inner(&mut self, state: &mut DebuggerState, ui: &Ui) {
        if let Some(tab_bar) = ui.tab_bar("Resources") {
            for state in &state.process_state {
                if let Some(tab) = ui.tab_item(format!("Resources ({})", state.process.0)) {


                    if let Ok(resources) = linux_fd_info::get_fd_info(state.process.0) {
                        let mut files = Vec::new();
                        let mut sockets = Vec::new();
                        let mut pipes = Vec::new();

                        for (fd, info) in resources {
                            if let Some(link) = info.link.clone() {
                                match link {
                                    FdLink::Path(path) => files.push((fd, info.clone(), path.to_string())),
                                    FdLink::Socket(socket) => sockets.push((fd, info.clone(), socket.clone())),
                                    FdLink::Pipe(pipe) => pipes.push((fd, info.clone(), pipe.clone())),
                                    _ => {}
                                }
                            }
                        }

                        ui.text("Open files:");
                        if let Some(table) = ui.begin_table_header(
                            format!("Files ({})", state.process.0),
                            [
                                TableColumnSetup::new("fd"),
                                TableColumnSetup::new("Flags"),
                                TableColumnSetup::new("Path"),
                            ],
                        ) {
                            for (fd, info, path) in files {
                                ui.table_next_column();
                                ui.text(format!("{}", fd));
                                ui.table_next_column();
                                ui.text(format!("{}", info.flags));
                                ui.table_next_column();
                                ui.text(path);
                            }

                            table.end();
                        }

                        ui.text("Open pipes:");
                        if let Some(table) = ui.begin_table_header(
                            format!("Pipes ({})", state.process.0),
                            [
                                TableColumnSetup::new("fd"),
                                TableColumnSetup::new("Pipeid"),
                            ],
                        ) {
                            for (fd, info, path) in pipes {
                                ui.table_next_column();
                                ui.text(format!("{}", fd));
                                ui.table_next_column();
                                ui.text(path);
                            }

                            table.end();
                        }

                        ui.text("Open sockets:");
                        if let Some(table) = ui.begin_table_header(
                            format!("Sockets ({})", state.process.0),
                            [
                                TableColumnSetup::new("fd"),
                                TableColumnSetup::new("SocketId"),
                            ],
                        ) {
                            for (fd, info, path) in sockets {
                                ui.table_next_column();
                                ui.text(format!("{}", fd));
                                ui.table_next_column();
                                ui.text(path);
                            }

                            table.end();
                        }
                    }


                    tab.end();
                }
            }
            tab_bar.end();
        }
    }
}