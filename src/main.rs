#![feature(seek_stream_len)]
#![feature(new_uninit)]

use crate::debugger_ui::{DebuggerState, DebuggerUi};
use clap::{App, Arg};
use debugging_client::{DebuggerMsg, DebuggingClient, Msg};

pub mod breakpoints;
pub mod debugger_ui;
pub mod debugging_client;
pub mod debugging_info;
pub mod elf;
pub mod memory_map;
pub mod registers;
pub mod stack;
pub mod ui;

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
