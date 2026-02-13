//! SR98 module -- Control SR98 RFID reader/writer for T5577 transponders.
//!
//! The SR98 is a USB HID RFID device capable of reading and writing T5577
//! RFID transponders. T5577 chips are commonly used in access control
//! systems and can emulate various card formats (HID, EM4100, etc.).
//!
//! Requires a HID library crate (e.g., `hidapi`) for USB device communication.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "sr98",
    full_name: "RF module for SR98 device and T5577 target",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 4] = [
    Command { name: "beep", description: "Beep!",                     handler: cmd_beep },
    Command { name: "raw",  description: "Write raw blocks to T5577", handler: cmd_raw },
    Command { name: "list", description: "List SR98 devices",         handler: cmd_list },
    Command { name: "hid",  description: "Write HID format to T5577", handler: cmd_hid },
];

// SR98 USB identifiers
// Vendor ID: 0x6688
// Product ID: 0x6850

// ===========================================================================
// sr98::beep
// ===========================================================================

fn cmd_beep(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: sr98::beep not yet implemented");
    eprintln!("  This command sends a beep command to the SR98 device.");
    eprintln!("  Requires:");
    eprintln!("    - HID library for USB device communication");
    eprintln!("    - Sending the beep HID report (command byte 0x03)");
    Status::Unsuccessful
}

// ===========================================================================
// sr98::raw
// ===========================================================================

fn cmd_raw(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: sr98::raw not yet implemented");
    eprintln!("  This command writes raw data blocks to a T5577 transponder.");
    eprintln!("  Requires:");
    eprintln!("    - /b0:XXXXXXXX /b1:XXXXXXXX ... (block data as 32-bit hex values)");
    eprintln!("    - T5577 supports 8 data blocks (0-7) of 32 bits each");
    eprintln!("    - Block 0 contains the configuration (modulation, bit rate, etc.)");
    eprintln!("    - Write command: 0x02, followed by block number and 4 data bytes");
    Status::Unsuccessful
}

// ===========================================================================
// sr98::list
// ===========================================================================

fn cmd_list(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: sr98::list not yet implemented");
    eprintln!("  This command enumerates connected SR98 USB HID devices.");
    eprintln!("  Requires:");
    eprintln!("    - HID library for USB device enumeration");
    eprintln!("    - Filtering by vendor ID 0x6688, product ID 0x6850");
    Status::Unsuccessful
}

// ===========================================================================
// sr98::hid
// ===========================================================================

fn cmd_hid(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: sr98::hid not yet implemented");
    eprintln!("  This command writes HID (iCLASS) format data to a T5577 transponder,");
    eprintln!("  cloning a HID proximity card.");
    eprintln!("  Requires:");
    eprintln!("    - /fc:NNN -- facility code (0-255)");
    eprintln!("    - /cn:NNNNN -- card number (0-65535)");
    eprintln!("    - Encoding the facility code and card number into 26-bit HID format");
    eprintln!("    - Writing the encoded data to T5577 blocks with appropriate config");
    eprintln!("    - Block 0 config: FSK2a, 50 kbps, max block 2");
    Status::Unsuccessful
}
