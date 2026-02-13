//! Next Generation Cryptography (NGC) module -- Windows Hello credential operations.
//!
//! NGC is the Windows Hello subsystem that manages PIN-based and biometric
//! authentication. This module provides commands for enumerating NGC containers,
//! decrypting PIN protectors, and performing sign/decrypt operations with
//! NGC keys.
//!
//! All commands require Windows and access to the NGC key storage, which is
//! located at: C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc

#![allow(dead_code)]

use crate::module::{Command, Module, Status};

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "ngc",
    full_name: "Next Generation Cryptography module (kiwi use only)",
    description: "Some commands to enumerate credentials...",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 5] = [
    Command { name: "logondata", description: ":)",                          handler: cmd_logondata },
    Command { name: "pin",      description: "Try to decrypt a PIN Protector", handler: cmd_pin },
    Command { name: "sign",     description: "Try to sign",                  handler: cmd_sign },
    Command { name: "decrypt",  description: "Try to decrypt",               handler: cmd_decrypt },
    Command { name: "enum",     description: "Enumerate NGC credentials",    handler: cmd_enum },
];

// ===========================================================================
// ngc::logondata
// ===========================================================================

fn cmd_logondata(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ngc::logondata not yet implemented");
    eprintln!("  This command extracts NGC logon data from the NGC key storage.");
    eprintln!("  Requires:");
    eprintln!("    - Access to NGC container files (SYSTEM privileges or backup of NGC folder)");
    eprintln!("    - DPAPI master key to decrypt the protector blobs");
    eprintln!("    - Parsing of the NGC container metadata (1.dat, protectors/*.dat)");
    Status::Unsuccessful
}

// ===========================================================================
// ngc::pin
// ===========================================================================

fn cmd_pin(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ngc::pin not yet implemented");
    eprintln!("  This command attempts to decrypt an NGC PIN protector.");
    eprintln!("  Requires:");
    eprintln!("    - /in:protector.dat -- path to the PIN protector file");
    eprintln!("    - /pin:NNNN -- the PIN to test (or brute-force range)");
    eprintln!("    - The protector is encrypted with DPAPI using a key derived from the PIN");
    eprintln!("    - PIN derivation: PBKDF2-SHA256(SHA256(UTF16LE(PIN)), salt, rounds)");
    eprintln!("    - Successful decryption yields the NGC private key");
    Status::Unsuccessful
}

// ===========================================================================
// ngc::sign
// ===========================================================================

fn cmd_sign(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ngc::sign not yet implemented");
    eprintln!("  This command uses a decrypted NGC key to perform a signature operation.");
    eprintln!("  Requires:");
    eprintln!("    - A decrypted NGC RSA private key (from ngc::pin or ngc::decrypt)");
    eprintln!("    - /data:hex_data -- the data to sign");
    eprintln!("    - Uses RSA-PKCS1-v1.5 or RSA-PSS signing with SHA-256");
    eprintln!("    - On Windows, can also use NCryptSignHash with the software KSP");
    Status::Unsuccessful
}

// ===========================================================================
// ngc::decrypt
// ===========================================================================

fn cmd_decrypt(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ngc::decrypt not yet implemented");
    eprintln!("  This command uses a decrypted NGC key to perform a decryption operation.");
    eprintln!("  Requires:");
    eprintln!("    - A decrypted NGC RSA private key");
    eprintln!("    - /data:hex_data -- the data to decrypt");
    eprintln!("    - Uses RSA-OAEP decryption with SHA-256");
    eprintln!("    - On Windows, can also use NCryptDecrypt with the software KSP");
    Status::Unsuccessful
}

// ===========================================================================
// ngc::enum
// ===========================================================================

fn cmd_enum(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ngc::enum not yet implemented");
    eprintln!("  This command enumerates NGC credential containers on the system.");
    eprintln!("  NGC containers are stored at:");
    eprintln!("    C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\");
    eprintln!("  Each container directory contains:");
    eprintln!("    - 1.dat          -- container metadata (GUID, user SID, provider)");
    eprintln!("    - Protectors\\    -- directory of protector blobs (PIN, bio, recovery)");
    eprintln!("      - 1.dat        -- first protector (usually PIN)");
    eprintln!("  Requires SYSTEM privileges or a backup of the NGC directory.");
    Status::Unsuccessful
}
