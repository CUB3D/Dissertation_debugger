#![feature(seek_stream_len)]
#![feature(new_uninit)]

use std::collections::HashMap;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult};
use imgui::{im_str, StyleColor, Window};
use libc::user;
use ptrace::{Breakpoint, BreakpointAction, Event, FpRegs, Process, Ptrace, UserRegs};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::iter::Iterator;
use std::ops::ControlFlow::Break;
use std::time::Duration;
use gimli::EndianSlice;
use debugging_client::{Msg, DebuggingClient, DebuggerMsg};

pub mod elf;
pub mod ui;
pub mod debugging_info;
pub mod debugger_ui;
pub mod debugging_client;

fn main() {
    let binary = std::env::args().nth(1).expect("No binary provided");
    println!("Loading {}", binary);
    let mut binary_content = std::fs::read(&binary).expect("Failed to read binary");
    let elf_parsed = elf::parse(&mut Cursor::new(binary_content)).expect("Failed to parse elf");

    let system = ui::init("Debugger");

    let mut dc = debugging_client::NativeDebuggingClient::default();

    let (sender,rec_from_debug) = dc.start(binary);


    let mut auto_stp = false;
    let mut single_step_mode = false;
    let mut started = false;
    let mut current_breakpoint: Option<Breakpoint> = None;

    let mut debugger_ui = debugger_ui::DebuggerUi::default();
    let mut debugger_state = debugger_ui::DebuggerState::default();
    debugger_state.elf = Some(elf_parsed);

    system.main_loop(move |_, ui| {
        if let Ok(msg) = rec_from_debug.recv_timeout(Duration::from_nanos(1)) {
            match msg {
                DebuggerMsg::Trap { user_regs, fp_regs } => {
                    debugger_state.cache_user_regs = Some(user_regs);
                    if auto_stp {
                        sender.send(Msg::Continue);
                    }
                }
                DebuggerMsg::SyscallTrap { user_regs, fp_regs } => {
                    let proc = debugger_state.process.expect("Got syscalltrap without a process????????");

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

                    debugger_state.syscall_list.push(syscall_desc);
                    debugger_state.cache_user_regs = Some(user_regs);
                    if auto_stp {
                        sender.send(Msg::Continue);
                    }
                }
                DebuggerMsg::BPTrap { user_regs, fp_regs, breakpoint} => {
                    // int3 never auto continues
                    debugger_state.cache_user_regs = Some(user_regs);
                    current_breakpoint = Some(breakpoint);
                }
                DebuggerMsg::ProcessSpwn(p) => {
                    debugger_state.process = Some(p);
                }
            }
        }

        let mut send_continue = || {
            if let Some(bp) = current_breakpoint {
                sender.send(Msg::DoSingleStep).expect("Failed to send msg");
                sender.send(Msg::InstallBreakpoint { address: bp.address }).expect("Failed to send msg");
                current_breakpoint = None;
            }
            sender.send(Msg::Continue).expect("Failed to send msg");
        };

        Window::new(im_str!("Controls")).build(ui, || {
            if ui.small_button(im_str!("|>")) {
                sender.send(Msg::Start).expect("Failed to send msg");
                started = true;
            }
            if started {
                if ui.checkbox(im_str!("Auto step"), &mut auto_stp) {
                    if auto_stp {
                        send_continue();
                    }
                }
                if !auto_stp {
                    if ui.small_button(im_str!("Step")) {
                        send_continue();
                    }
                }

                if ui.checkbox(im_str!("Single step mode"), &mut single_step_mode) {
                    sender
                        .send(Msg::SingleStep(single_step_mode))
                        .expect("Failed to send msg");
                }
            }
        });
        debugger_ui.render(ui, &mut debugger_state);
    });
}
