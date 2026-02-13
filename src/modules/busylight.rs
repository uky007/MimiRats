//! BusyLight module -- Control Kuando/Plenom BusyLight USB devices.
//!
//! BusyLight devices are USB HID presence indicators commonly used with
//! UC platforms (Skype, Teams, etc.). This module provides commands to
//! enumerate devices, query status, set colors, and turn them off.
//!
//! Requires a HID library crate (e.g., `hidapi`) for USB device communication.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "busylight",
    full_name: "BusyLight module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 4] = [
    Command { name: "list",   description: "List BusyLight devices",  handler: cmd_list },
    Command { name: "status", description: "Display device status",   handler: cmd_status },
    Command { name: "single", description: "Set a single color",      handler: cmd_single },
    Command { name: "off",    description: "Turn off",                handler: cmd_off },
];

// BusyLight USB identifiers
// Vendor ID: 0x27BB (Kuando / Plenom)
// Product IDs: 0x3BCA (BusyLight UC Omega), 0x3BCB, 0x3BCC, etc.

// ===========================================================================
// busylight::list
// ===========================================================================

fn cmd_list(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: busylight::list not yet implemented");
    eprintln!("  This command enumerates connected BusyLight USB HID devices.");
    eprintln!("  Requires:");
    eprintln!("    - HID library (hidapi crate) for USB device enumeration");
    eprintln!("    - Filtering by vendor ID 0x27BB (Kuando/Plenom)");
    eprintln!("    - Lists: device path, product string, serial number");
    Status::Unsuccessful
}

// ===========================================================================
// busylight::status
// ===========================================================================

fn cmd_status(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: busylight::status not yet implemented");
    eprintln!("  This command queries the current status of a BusyLight device.");
    eprintln!("  Requires:");
    eprintln!("    - Opening the HID device and sending a status request");
    eprintln!("    - Parsing the 64-byte response: current color, ringtone, keepalive");
    Status::Unsuccessful
}

// ===========================================================================
// busylight::single
// ===========================================================================

fn cmd_single(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: busylight::single not yet implemented");
    eprintln!("  This command sets a BusyLight to a single solid color.");
    eprintln!("  Requires:");
    eprintln!("    - /red:N /green:N /blue:N (0-255 each)");
    eprintln!("    - Sending a 64-byte HID report with the color values");
    eprintln!("    - BusyLight protocol: Step 0: color(R,G,B), on_time=1, off_time=0");
    Status::Unsuccessful
}

// ===========================================================================
// busylight::off
// ===========================================================================

fn cmd_off(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: busylight::off not yet implemented");
    eprintln!("  This command turns off the BusyLight (sets color to black, stops ringtone).");
    eprintln!("  Requires:");
    eprintln!("    - Sending a 64-byte HID report with all color values set to 0");
    eprintln!("    - Setting ringtone to 0 (silence)");
    Status::Unsuccessful
}
