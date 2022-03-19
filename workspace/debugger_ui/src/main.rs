//! Implements the ui for the debugger

#![feature(seek_stream_len)]
#![feature(new_uninit)]

use crate::debugger_ui::DebuggerUi;
use clap::{App, Arg};
use debugger_core::debugger_state::DebuggerState;

pub mod breakpoints;
pub mod call_stack;
pub mod child_process;
pub mod controls;
pub mod debugger_ui;
pub mod debugging_info;
pub mod disassemble;
pub mod elf_info;
pub mod memory_map;
pub mod memory_view;
pub mod registers;
pub mod syscall;
pub mod ui;

///disassemble should have lines for branches
// should be able to pause in place (maybe we can send a sigstop?)
// save snapshots?
// have a log so that prints are visible in the gui

// Needed for other things:
// breakpoints api that works

fn main() {
    let matches = App::new("debugger")
        .version("v0.1")
        .author("Callum Thomson")
        .about("A debugger")
        .arg(
            Arg::with_name("binary")
                .value_name("target")
                .help("The path to the binary to debug")
                .takes_value(true)
                .required(false),
        )
        .get_matches();

    let mut debugger_state = DebuggerState::default();

    if let Some(binary) = matches.value_of("binary") {
        debugger_state.load_binary(&binary);
    }
    DebuggerUi::init(debugger_state);
}
