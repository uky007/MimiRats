//! Event module — Windows Event Log management.
//!
//! Provides commands for clearing event logs and (planned) in-memory log patching.

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "event",
    full_name: "Event module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 2] = [
    Command {
        name: "drop",
        description: "Patch Events service to avoid new events",
        handler: cmd_drop,
    },
    Command {
        name: "clear",
        description: "Clear an event log",
        handler: cmd_clear,
    },
];

// ---------------------------------------------------------------------------
// Windows implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_clear(args: &[String]) -> Status {
    use crate::display::find_named_arg;
    use windows::Win32::System::EventLog::*;
    use windows::core::PCWSTR;

    let log_name = match find_named_arg(args, "log") {
        Some(name) => name,
        None => {
            eprintln!("ERROR: event log name (/log:Security) is missing");
            return Status::Unsuccessful;
        }
    };

    let wide_name: Vec<u16> = log_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let handle = match OpenEventLogW(PCWSTR::null(), PCWSTR(wide_name.as_ptr())) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ERROR: OpenEventLog(\"{}\"): {}", log_name, e);
                return Status::Unsuccessful;
            }
        };

        let result = match ClearEventLogW(handle, PCWSTR::null()) {
            Ok(()) => {
                println!("ClearEventLog(\"{}\") : OK !", log_name);
                Status::Success
            }
            Err(e) => {
                eprintln!("ERROR: ClearEventLog(\"{}\"): {}", log_name, e);
                Status::Unsuccessful
            }
        };

        let _ = CloseEventLog(handle);
        result
    }
}

#[cfg(not(windows))]
fn cmd_clear(_args: &[String]) -> Status {
    eprintln!("ERROR: event::clear requires Windows");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// drop — stub (requires memory patching of the Event Log service)
// ---------------------------------------------------------------------------

fn cmd_drop(_args: &[String]) -> Status {
    eprintln!("ERROR: event::drop not yet implemented");
    eprintln!("       This command requires patching the Event Log service in memory");
    eprintln!("       to prevent new events from being recorded.");
    Status::Unsuccessful
}
