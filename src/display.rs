//! Display and formatting utilities for MimiRats.
//! Provides hex dump, SID/GUID formatting, FILETIME conversion, and argument parsing.
#[allow(dead_code)]

/// Print a classic hexadecimal + ASCII dump of `data` to stdout.
pub fn hex_dump(data: &[u8]) {
    // Classic hex dump: offset, 16 hex bytes, ASCII representation
    // Format like:
    // 00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 00 00 00 00 00  |Hello World.....|
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:08x}  ", i * 16);
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }
        // Pad if less than 16 bytes
        for j in chunk.len()..16 {
            print!("   ");
            if j == 7 {
                print!(" ");
            }
        }
        print!(" |");
        for byte in chunk {
            if *byte >= 0x20 && *byte < 0x7f {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

#[allow(dead_code)]
pub fn format_sid(sid_bytes: &[u8]) -> String {
    // Parse Windows SID binary format:
    // Byte 0: revision (1)
    // Byte 1: sub-authority count
    // Bytes 2-7: authority (6 bytes, big-endian u48)
    // Bytes 8+: sub-authorities (each u32 LE)
    // Format: S-1-5-21-xxx-xxx-xxx-xxx
    if sid_bytes.len() < 8 {
        return String::from("(invalid SID)");
    }
    let revision = sid_bytes[0];
    let sub_count = sid_bytes[1] as usize;
    let authority = ((sid_bytes[2] as u64) << 40)
        | ((sid_bytes[3] as u64) << 32)
        | ((sid_bytes[4] as u64) << 24)
        | ((sid_bytes[5] as u64) << 16)
        | ((sid_bytes[6] as u64) << 8)
        | (sid_bytes[7] as u64);
    let mut result = format!("S-{}-{}", revision, authority);
    for i in 0..sub_count {
        let offset = 8 + i * 4;
        if offset + 4 > sid_bytes.len() {
            break;
        }
        let sub = u32::from_le_bytes([
            sid_bytes[offset],
            sid_bytes[offset + 1],
            sid_bytes[offset + 2],
            sid_bytes[offset + 3],
        ]);
        result.push_str(&format!("-{}", sub));
    }
    result
}

pub fn format_guid(guid_bytes: &[u8]) -> String {
    // Parse 16-byte GUID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    // First 3 parts are little-endian, last 2 are big-endian
    if guid_bytes.len() < 16 {
        return String::from("(invalid GUID)");
    }
    let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
    let d3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        d1,
        d2,
        d3,
        guid_bytes[8],
        guid_bytes[9],
        guid_bytes[10],
        guid_bytes[11],
        guid_bytes[12],
        guid_bytes[13],
        guid_bytes[14],
        guid_bytes[15]
    )
}

#[allow(dead_code)]
pub fn format_filetime(ft: u64) -> String {
    // FILETIME: 100-nanosecond intervals since 1601-01-01
    // Convert to Unix timestamp: subtract 116444736000000000, divide by 10000000
    if ft == 0 {
        return String::from("(never)");
    }
    let unix_ts = (ft as i64 - 116444736000000000i64) / 10000000;
    use chrono::{DateTime, Utc};
    match DateTime::<Utc>::from_timestamp(unix_ts, 0) {
        Some(dt) => dt.format("%Y/%m/%d %H:%M:%S").to_string(),
        None => format!("(invalid: {})", ft),
    }
}

/// Parse mimikatz-style named arguments: /name:value
/// Returns the value portion if a matching `/name:value` argument is found.
pub fn find_named_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let prefix = format!("/{}:", name);
    for arg in args {
        if let Some(val) = arg.strip_prefix(&prefix) {
            return Some(val);
        }
    }
    None
}

/// Check for a boolean flag argument: /flag
#[allow(dead_code)]
pub fn has_named_flag(args: &[String], name: &str) -> bool {
    let flag = format!("/{}", name);
    args.iter().any(|arg| arg.eq_ignore_ascii_case(&flag))
}
