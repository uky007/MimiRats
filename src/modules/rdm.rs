//! RDM module -- Control RDM (830 AL) RFID reader device.
//!
//! The RDM-830 is a USB HID 125 kHz RFID reader. This module provides
//! commands for listing connected devices and querying firmware version
//! information.
//!
//! Requires a HID library crate (e.g., `hidapi`) for USB device communication.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "rdm",
    full_name: "RF module for RDM(830 AL) device",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 2] = [
    Command { name: "version", description: "Display RDM device version", handler: cmd_version },
    Command { name: "list",    description: "List RDM devices",           handler: cmd_list },
];

// RDM-830 USB identifiers
// Vendor ID: 0x6688
// Product ID: 0x6850 (shared with SR98 in some models)

// ===========================================================================
// rdm::version
// ===========================================================================

fn cmd_version(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: rdm::version not yet implemented");
    eprintln!("  This command queries the firmware version of a connected RDM-830 device.");
    eprintln!("  Requires:");
    eprintln!("    - HID library for USB device communication");
    eprintln!("    - Sending the version query command (0x01) via HID report");
    eprintln!("    - Parsing the response: firmware version string, hardware revision");
    Status::Unsuccessful
}

// ===========================================================================
// rdm::list
// ===========================================================================

fn cmd_list(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: rdm::list not yet implemented");
    eprintln!("  This command enumerates connected RDM-830 USB HID RFID readers.");
    eprintln!("  Requires:");
    eprintln!("    - HID library for USB device enumeration");
    eprintln!("    - Filtering by known RDM vendor/product IDs");
    eprintln!("    - Lists: device path, product string, serial number");
    Status::Unsuccessful
}
