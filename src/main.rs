#![feature(seek_stream_len)]

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

pub mod elf;
pub mod ui;
pub mod debugging_info;
pub mod debugger_ui;

enum Msg {
    Start,
    Continue,
    SingleStep(bool),
    AddBreakpoint(Breakpoint),
    /// Install the breakpoint that has already been added at the given address
    InstallBreakpoint { address: usize },
    DoSingleStep,
}

#[derive(Clone, Debug)]
pub enum DebuggerMsg {
    /// The child has hit a singlestep breakpoint, control returned to caller
    Trap {
        user_regs: Box<UserRegs>,
        fp_regs: Box<FpRegs>,
    },
    /// The child has hit a int3 breakpoint, control returned to caller
    BPTrap {
        user_regs: Box<UserRegs>,
        fp_regs: Box<FpRegs>,
        breakpoint: Breakpoint,
    },
    /// The child has hit a syscall breakpoint, control returned to caller
    SyscallTrap {
        user_regs: Box<UserRegs>,
        fp_regs: Box<FpRegs>,
    },
    /// The process has spawned
    ProcessSpwn(Process),
}


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

fn main() {
    let binary = std::env::args().nth(1).expect("No binary provided");
    let load_address = 0x555555554000;
    println!("Loading {}", binary);
    let mut binary_content = std::fs::read(&binary).expect("Failed to read binary");
    let elf_parsed = elf::parse(&mut Cursor::new(binary_content)).expect("Failed to parse elf");

    let subprograms = debugging_info::parse_dwarf_info(&elf_parsed).subprograms;

    let mut resolver = Box::new(MySymbolResolver::default());
    for prog in &subprograms {
        resolver.map.insert(prog.start_addr + load_address, prog.name.clone());
    }

    let system = ui::init("Debugger");

    let (send_from_debug, rec_from_debug) = std::sync::mpsc::channel();
    let (sender, reciever) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let mut debugger =
            Ptrace::new(&binary, "Debuggee", "").expect("Failed to start process under ptrace");

        let msg = reciever.recv().expect("failed to get msg");
        match msg {
            Msg::Start => {
                let child = debugger.inital_spawn_child();

                let mut local_debugger_state = debugger_ui::DebuggerState::default();

                // let mut bp = Breakpoint::new(0x00005555555551b8);
                // bp.install(child);

                send_from_debug
                    .send(DebuggerMsg::ProcessSpwn(child))
                    .expect("Send proc");

                child.ptrace_singlestep();

                let mut is_singlestep = false;
                let mut in_syscall = false;

                loop {
                    let status = child.wait_for();

                    if status.wifstopped() {
                        let stopsig = status.wstopsig();
                        if stopsig == (libc::SIGTRAP | 0x80) {
                            if !in_syscall {
                                send_from_debug.send(DebuggerMsg::SyscallTrap {
                                    user_regs: child.ptrace_getregs(),
                                    fp_regs: child.ptrace_getfpregs(),
                                })
                                    .expect("Faeild to send from debug");
                            } else {
                                child.ptrace_syscall();
                                in_syscall = false;
                                continue;
                            }
                            in_syscall = !in_syscall;
                            // println!("syscall");
                        } else if stopsig == libc::SIGTRAP {
                            // println!("sigtrap");
                            let event = status.0 >> 16;

                            let mut regs = child.ptrace_getregs();

                            if event == 0 {
                                // We know we didnt hit a syscall but we might have hit a manual breakpoint, check if we hit a 0xcc
                                if child.ptrace_peektext(regs.ip as usize - 1)
                                    & 0xFF
                                    == 0xCC
                                {
                                    println!(
                                        "Hit a breakpoint @ 0x{:x} ::: {:X}",
                                        regs.ip,
                                        child.ptrace_peektext(
                                            regs.ip as usize - 1
                                        )
                                    );
                                    let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == regs.ip as usize - 1).expect("Hit a breakpoint, but we can't find it to uninstall");
                                    bp.uninstall(child);
                                    // Go back to the start of the original instruction so it actually gets executed
                                    unsafe { libc::ptrace(libc::PTRACE_POKEUSER, child, 8 * libc::RIP, regs.ip - 1) };
                                    regs.ip -= 1;

                                    //TODO: Testing, we shouldnt step after removing the bp so that the state can be seen before the bp
                                    // child.ptr/ace_singlestep();
                                    // child.wait_for();
                                    // bp.install(child);
                                    // TODO: Testing

                                    send_from_debug
                                        .send(DebuggerMsg::BPTrap {
                                            user_regs: regs,
                                            fp_regs: child.ptrace_getfpregs(),
                                            breakpoint: *bp,
                                        })
                                        .expect("Faeild to send from debug");
                                } else {
                                    send_from_debug
                                        .send(DebuggerMsg::Trap {
                                            user_regs: regs,
                                            fp_regs: child.ptrace_getfpregs(),
                                        })
                                        .expect("Faeild to send from debug");
                                }
                            }
                        }
                    }

                    loop {
                        match reciever.recv().expect("No continue") {
                            Msg::Continue => break,
                            Msg::SingleStep(s) => is_singlestep = s,
                            Msg::AddBreakpoint(bp) => {
                                local_debugger_state.breakpoints.push(bp);
                                let bp = local_debugger_state.breakpoints.last_mut().unwrap();
                                let success = bp.install(child);
                                println!("Installed bp at {:?}, success: {}", bp, success);
                            },
                            Msg::DoSingleStep => {
                                child.ptrace_singlestep();
                                child.wait_for();
                            }
                            Msg::InstallBreakpoint { address } => {
                                let bp = local_debugger_state.breakpoints.iter_mut().find(|bp| bp.address == address).expect("Attempt to install breakpoint that has not been added");
                                bp.install(child);
                            }
                            _ => panic!("unexpected msg"),
                        }
                    }

                    if is_singlestep {
                        child.ptrace_singlestep();
                    } else {
                        child.ptrace_syscall();
                    }
                }
            }
            _ => {}
        }
    });
    let mut auto_stp = false;
    let mut single_step_mode = false;
    let mut started = false;
    let mut current_breakpoint: Option<Breakpoint> = None;

    let mut window_stack = false;
    let mut window_info = false;

    let mut debugger_ui = debugger_ui::DebuggerUi::default();
    let mut debugger_state = debugger_ui::DebuggerState::default();

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

        if window_info {
            Window::new(im_str!("Info")).build(ui, || {
                ui.text(im_str!("Entry point: 0x{:X}", elf_parsed.entry_point));
                ui.text(im_str!("Section count: 0x{:X}", elf_parsed.sections.len()));
                if let Some(p) = debugger_state.process {
                    ui.text(im_str!("proc: {}", p.0));
                }
            });
        }

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

        if started {
            Window::new(im_str!("Decode")).build(ui, || {
                if let Some(user_regs) = &debugger_state.cache_user_regs {
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

                                let bp = debugger_state.breakpoints.iter().find(|bp| bp.address == instruction.ip() as usize);
                                let bp_text = if bp.is_some() {
                                    "B "
                                } else {
                                    "  "
                                };

                                if ui.small_button(&im_str!("{}{:016X} {}", bp_text, instruction.ip(), output)) {
                                    if let Some(pos) = debugger_state.breakpoints.iter().position(|bp| bp.address == instruction.ip() as usize) {
                                        debugger_state.breakpoints.remove(pos);
                                    } else {
                                        let bp = Breakpoint::new(instruction.ip() as usize);
                                        debugger_state.breakpoints.push(bp);
                                        sender.send(Msg::AddBreakpoint(bp));
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
            });

            if window_stack {
                Window::new(im_str!("Stack")).build(ui, || {
                    if let Some(process) = debugger_state.process {
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
                });
            }
        }
        debugger_ui.render(ui, &mut debugger_state);
    });
}
