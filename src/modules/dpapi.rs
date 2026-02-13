//! DPAPI module -- Data Protection API master key file parsing.
//!
//! Parses DPAPI master key files to extract the encrypted master key data,
//! backup key data, credential history, and domain key information.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
use crate::display;

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "dpapi",
    full_name: "DPAPI module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 1] = [
    Command { name: "masterkeys", description: "Display masterkey file information", handler: cmd_masterkeys },
];

// ===========================================================================
// DPAPI Master Key file structures
// ===========================================================================

/// DPAPI Master Key file header (version 2).
///
/// Layout:
///   +0x00: u32  version (should be 2)
///   +0x04: [u8; 16]  provider GUID
///   +0x14: u32  mk_version (master key version)
///   +0x18: [u8; 16]  GUID (the master key GUID, used as filename)
///   +0x28: u32  flags
///   +0x2C: u16  name_len (in bytes, UTF-16)
///   +0x2E: [u8; name_len]  name data (UTF-16-LE)
///
/// After the name, the file contains:
///   - Master key blob
///   - Backup key blob
///   - Credential history blob
///   - Domain key blob
///
/// Each blob has its own length prefix.

const DPAPI_HEADER_MIN_SIZE: usize = 0x2E;

/// Read a little-endian u16 from a byte slice.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from a byte slice.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian u64 from a byte slice.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

// ===========================================================================
// dpapi::masterkeys
// ===========================================================================

fn cmd_masterkeys(args: &[String]) -> Status {
    let path = match display::find_named_arg(args, "in") {
        Some(p) => p,
        None => {
            eprintln!("ERROR: /in:path_to_masterkey_file required");
            eprintln!("  Usage: dpapi::masterkeys /in:C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-...\\<GUID>");
            return Status::Unsuccessful;
        }
    };

    println!("\nReading DPAPI master key file: {}\n", path);

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("ERROR: Failed to read file '{}': {}", path, e);
            return Status::Unsuccessful;
        }
    };

    if data.len() < DPAPI_HEADER_MIN_SIZE {
        eprintln!("ERROR: File too small to be a valid DPAPI master key file ({} bytes)", data.len());
        return Status::Unsuccessful;
    }

    // Parse header
    let version = read_u32_le(&data, 0x00);
    let provider_guid = &data[0x04..0x14];
    let mk_version = read_u32_le(&data, 0x14);
    let key_guid = &data[0x18..0x28];
    let flags = read_u32_le(&data, 0x28);
    let name_len = read_u16_le(&data, 0x2C) as usize;

    println!("  Version      : {}", version);
    println!("  Provider     : {}", display::format_guid(provider_guid));
    println!("  MK Version   : {}", mk_version);
    println!("  GUID         : {}", display::format_guid(key_guid));
    println!("  Flags        : 0x{:08X}", flags);

    // Parse name (UTF-16-LE)
    let name_start = 0x2E;
    if name_start + name_len <= data.len() && name_len > 0 {
        let name_bytes = &data[name_start..name_start + name_len];
        let u16_count = name_len / 2;
        let mut chars = Vec::with_capacity(u16_count);
        for i in 0..u16_count {
            chars.push(read_u16_le(name_bytes, i * 2));
        }
        let name = String::from_utf16_lossy(&chars);
        println!("  Name         : {}", name);
    }

    // After the name, parse the blob headers
    let mut offset = name_start + name_len;

    // Master key blob
    if offset + 8 <= data.len() {
        let mk_blob_version = read_u32_le(&data, offset);
        offset += 4;
        // The master key blob starts with its own header
        // For a basic parse, we just show the sizes
        println!("\n  [Master Key Blob]");
        println!("    Version    : {}", mk_blob_version);

        if offset + 20 <= data.len() {
            let salt = &data[offset..offset + 16];
            offset += 16;
            let rounds = read_u32_le(&data, offset);
            offset += 4;

            println!("    Salt       : {}", hex::encode(salt));
            println!("    Rounds     : {}", rounds);

            // HMAC algorithm + crypto algorithm + key data follow
            if offset + 8 <= data.len() {
                let hmac_alg = read_u32_le(&data, offset);
                offset += 4;
                let crypto_alg = read_u32_le(&data, offset);
                offset += 4;

                let hmac_name = match hmac_alg {
                    0x8004 => "HMAC-SHA1 (0x8004)",
                    0x800C => "HMAC-SHA256 (0x800C)",
                    0x800D => "HMAC-SHA384 (0x800D)",
                    0x800E => "HMAC-SHA512 (0x800E)",
                    _ => "unknown",
                };
                let crypto_name = match crypto_alg {
                    0x6601 => "DES-CBC (0x6601)",
                    0x6603 => "3DES-CBC (0x6603)",
                    0x6610 => "AES-256-CBC (0x6610)",
                    0x6611 => "AES-192-CBC (0x6611)",
                    0x6612 => "AES-128-CBC (0x6612)",
                    _ => "unknown",
                };

                println!("    HMAC Alg   : {}", hmac_name);
                println!("    Crypto Alg : {}", crypto_name);

                // The encrypted key data follows; show a hex dump of the first portion
                let remaining = data.len() - offset;
                let dump_len = remaining.min(64);
                if dump_len > 0 {
                    println!("    Key data (first {} of {} bytes):", dump_len, remaining);
                    display::hex_dump(&data[offset..offset + dump_len]);
                }
            }
        }
    }

    println!("\n  File size    : {} bytes", data.len());

    if version != 2 {
        eprintln!("\nWARNING: Expected version 2, got {}. Parsing may be incorrect.", version);
    }

    Status::Success
}
