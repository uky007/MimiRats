//! System environment module — UEFI/EFI variable access.
//!
//! Lists, reads, sets, and deletes UEFI system environment variables
//! via `NtEnumerateSystemEnvironmentValuesEx` and related NT APIs.

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "sysenv",
    full_name: "System Environment Value module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 4] = [
    Command {
        name: "list",
        description: "List system environment variables",
        handler: cmd_list,
    },
    Command {
        name: "get",
        description: "Get a system environment variable",
        handler: cmd_get,
    },
    Command {
        name: "set",
        description: "Set a system environment variable",
        handler: cmd_set,
    },
    Command {
        name: "del",
        description: "Delete a system environment variable",
        handler: cmd_del,
    },
];

// ---------------------------------------------------------------------------
// Windows implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use windows::Win32::System::LibraryLoader::*;
    use windows::core::*;
    use crate::module::Status;
    use crate::display::find_named_arg;

    const STATUS_BUFFER_TOO_SMALL: i32 = 0xC0000023_u32 as i32;

    /// Helper: encode a Rust &str to a null-terminated wide string.
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Parse a GUID string like {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} into 16 bytes.
    fn parse_guid(s: &str) -> Option<[u8; 16]> {
        // Strip braces if present
        let s = s.trim_start_matches('{').trim_end_matches('}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return None;
        }
        let hex_str = parts.join("");
        if hex_str.len() != 32 {
            return None;
        }
        let bytes = hex::decode(&hex_str).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        // GUID on disk is mixed-endian:
        // Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE), Data4 (8 bytes BE)
        // But the input is already in display order (big-endian for each group),
        // so we need to swap the first three groups to LE.
        let mut guid = [0u8; 16];
        // Data1: swap 4 bytes
        guid[0] = bytes[3]; guid[1] = bytes[2]; guid[2] = bytes[1]; guid[3] = bytes[0];
        // Data2: swap 2 bytes
        guid[4] = bytes[5]; guid[5] = bytes[4];
        // Data3: swap 2 bytes
        guid[6] = bytes[7]; guid[7] = bytes[6];
        // Data4: 8 bytes as-is
        guid[8..16].copy_from_slice(&bytes[8..16]);
        Some(guid)
    }

    // NtApi function signatures
    type NtEnumerateSystemEnvironmentValuesExFn =
        unsafe extern "system" fn(info_class: u32, buffer: *mut u8, buffer_length: *mut u32) -> i32;
    type NtQuerySystemEnvironmentValueExFn =
        unsafe extern "system" fn(
            name: *const UNICODE_STRING,
            vendor_guid: *const [u8; 16],
            value: *mut u8,
            value_length: *mut u32,
            attributes: *mut u32,
        ) -> i32;
    type NtSetSystemEnvironmentValueExFn =
        unsafe extern "system" fn(
            name: *const UNICODE_STRING,
            vendor_guid: *const [u8; 16],
            value: *const u8,
            value_length: u32,
            attributes: u32,
        ) -> i32;

    // UNICODE_STRING structure for ntdll calls
    #[repr(C)]
    struct UNICODE_STRING {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    fn make_unicode_string(wide: &[u16]) -> UNICODE_STRING {
        // Length excludes null terminator, MaximumLength includes it
        let len_bytes = if wide.is_empty() {
            0
        } else {
            // Find null terminator
            let str_len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
            (str_len * 2) as u16
        };
        UNICODE_STRING {
            length: len_bytes,
            maximum_length: (wide.len() * 2) as u16,
            buffer: wide.as_ptr(),
        }
    }

    unsafe fn get_ntdll_proc<T>(name: &std::ffi::CStr) -> Option<T> {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let proc = GetProcAddress(ntdll, PCSTR(name.as_ptr() as *const u8))?;
        Some(std::mem::transmute_copy(&proc))
    }

    pub fn cmd_list(_args: &[String]) -> Status {
        println!("Requires SeSystemEnvironmentPrivilege");
        println!();

        unsafe {
            let func: NtEnumerateSystemEnvironmentValuesExFn = match get_ntdll_proc(
                c"NtEnumerateSystemEnvironmentValuesEx",
            ) {
                Some(f) => f,
                None => {
                    eprintln!("ERROR: Could not find NtEnumerateSystemEnvironmentValuesEx in ntdll");
                    return Status::Unsuccessful;
                }
            };

            // First call: get buffer size
            let mut size: u32 = 0;
            let status = func(1, std::ptr::null_mut(), &mut size);
            // STATUS_BUFFER_TOO_SMALL = 0xC0000023
            if status != STATUS_BUFFER_TOO_SMALL && status < 0 {
                eprintln!("ERROR: NtEnumerateSystemEnvironmentValuesEx(size): NTSTATUS 0x{:08x}", status as u32);
                return Status::Unsuccessful;
            }

            if size == 0 {
                println!("No system environment variables found.");
                return Status::Success;
            }

            // Second call: get actual data
            let mut buf = vec![0u8; size as usize];
            let status = func(1, buf.as_mut_ptr(), &mut size);
            if status < 0 {
                eprintln!("ERROR: NtEnumerateSystemEnvironmentValuesEx: NTSTATUS 0x{:08x}", status as u32);
                return Status::Unsuccessful;
            }

            // Parse VARIABLE_NAME_AND_VALUE entries
            // Each entry: u32 NextOffset, u32 ValueOffset, u32 ValueLength, u32 Attributes,
            //             GUID VendorGuid (16 bytes), WCHAR Name[...], BYTE Value[...]
            let mut offset = 0usize;
            loop {
                if offset + 32 > buf.len() {
                    break;
                }
                let next_offset = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
                let _value_offset = u32::from_le_bytes([buf[offset+4], buf[offset+5], buf[offset+6], buf[offset+7]]);
                let _value_length = u32::from_le_bytes([buf[offset+8], buf[offset+9], buf[offset+10], buf[offset+11]]);
                let attributes = u32::from_le_bytes([buf[offset+12], buf[offset+13], buf[offset+14], buf[offset+15]]);
                let guid_bytes = &buf[offset+16..offset+32];
                let guid = crate::display::format_guid(guid_bytes);

                // Name starts at offset+32 as null-terminated UTF-16
                let name_start = offset + 32;
                let mut name_end = name_start;
                while name_end + 1 < buf.len() {
                    let c = u16::from_le_bytes([buf[name_end], buf[name_end+1]]);
                    if c == 0 {
                        break;
                    }
                    name_end += 2;
                }
                let name_slice: Vec<u16> = buf[name_start..name_end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let name = String::from_utf16_lossy(&name_slice);

                println!("Name       : {}", name);
                println!("Vendor GUID: {}", guid);
                println!("Attributes : 0x{:08x}", attributes);
                println!();

                if next_offset == 0 {
                    break;
                }
                offset += next_offset as usize;
            }
        }
        Status::Success
    }

    pub fn cmd_get(args: &[String]) -> Status {
        println!("Requires SeSystemEnvironmentPrivilege");
        println!();

        let name = match find_named_arg(args, "name") {
            Some(n) => n,
            None => {
                eprintln!("ERROR: variable name (/name:VarName) is missing");
                return Status::Unsuccessful;
            }
        };
        let guid_str = match find_named_arg(args, "guid") {
            Some(g) => g,
            None => {
                eprintln!("ERROR: vendor GUID (/guid:{{...}}) is missing");
                return Status::Unsuccessful;
            }
        };
        let guid = match parse_guid(guid_str) {
            Some(g) => g,
            None => {
                eprintln!("ERROR: invalid GUID format");
                return Status::Unsuccessful;
            }
        };

        let wide_name = to_wide(name);
        let us_name = make_unicode_string(&wide_name);

        unsafe {
            let func: NtQuerySystemEnvironmentValueExFn = match get_ntdll_proc(
                c"NtQuerySystemEnvironmentValueEx",
            ) {
                Some(f) => f,
                None => {
                    eprintln!("ERROR: Could not find NtQuerySystemEnvironmentValueEx in ntdll");
                    return Status::Unsuccessful;
                }
            };

            // First call: get size
            let mut size: u32 = 0;
            let mut attributes: u32 = 0;
            let status = func(&us_name, &guid, std::ptr::null_mut(), &mut size, &mut attributes);
            if status != STATUS_BUFFER_TOO_SMALL && status < 0 {
                eprintln!("ERROR: NtQuerySystemEnvironmentValueEx(size): NTSTATUS 0x{:08x}", status as u32);
                return Status::Unsuccessful;
            }

            if size == 0 {
                println!("Variable \"{}\" is empty or not found.", name);
                return Status::Success;
            }

            // Second call: get value
            let mut buf = vec![0u8; size as usize];
            let status = func(&us_name, &guid, buf.as_mut_ptr(), &mut size, &mut attributes);
            if status < 0 {
                eprintln!("ERROR: NtQuerySystemEnvironmentValueEx: NTSTATUS 0x{:08x}", status as u32);
                return Status::Unsuccessful;
            }

            println!("Name       : {}", name);
            println!("Vendor GUID: {}", guid_str);
            println!("Attributes : 0x{:08x}", attributes);
            println!("Length     : {} bytes", size);
            crate::display::hex_dump(&buf[..size as usize]);
        }
        Status::Success
    }

    pub fn cmd_set(args: &[String]) -> Status {
        println!("Requires SeSystemEnvironmentPrivilege");
        println!();

        let name = match find_named_arg(args, "name") {
            Some(n) => n,
            None => {
                eprintln!("ERROR: variable name (/name:VarName) is missing");
                return Status::Unsuccessful;
            }
        };
        let guid_str = match find_named_arg(args, "guid") {
            Some(g) => g,
            None => {
                eprintln!("ERROR: vendor GUID (/guid:{{...}}) is missing");
                return Status::Unsuccessful;
            }
        };
        let value = match find_named_arg(args, "value") {
            Some(v) => v,
            None => {
                eprintln!("ERROR: value (/value:data) is missing");
                return Status::Unsuccessful;
            }
        };
        let guid = match parse_guid(guid_str) {
            Some(g) => g,
            None => {
                eprintln!("ERROR: invalid GUID format");
                return Status::Unsuccessful;
            }
        };

        let wide_name = to_wide(name);
        let us_name = make_unicode_string(&wide_name);
        let value_bytes = value.as_bytes();
        // EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
        let attributes: u32 = 0x00000007;

        unsafe {
            let func: NtSetSystemEnvironmentValueExFn = match get_ntdll_proc(
                c"NtSetSystemEnvironmentValueEx",
            ) {
                Some(f) => f,
                None => {
                    eprintln!("ERROR: Could not find NtSetSystemEnvironmentValueEx in ntdll");
                    return Status::Unsuccessful;
                }
            };

            let status = func(
                &us_name,
                &guid,
                value_bytes.as_ptr(),
                value_bytes.len() as u32,
                attributes,
            );
            if status < 0 {
                eprintln!("ERROR: NtSetSystemEnvironmentValueEx: NTSTATUS 0x{:08x}", status as u32);
                return Status::Unsuccessful;
            }

            println!("NtSetSystemEnvironmentValueEx(\"{}\") : OK !", name);
        }
        Status::Success
    }

    pub fn cmd_del(args: &[String]) -> Status {
        println!("Requires SeSystemEnvironmentPrivilege");
        println!();

        let name = match find_named_arg(args, "name") {
            Some(n) => n,
            None => {
                eprintln!("ERROR: variable name (/name:VarName) is missing");
                return Status::Unsuccessful;
            }
        };
        let guid_str = match find_named_arg(args, "guid") {
            Some(g) => g,
            None => {
                eprintln!("ERROR: vendor GUID (/guid:{{...}}) is missing");
                return Status::Unsuccessful;
            }
        };
        let guid = match parse_guid(guid_str) {
            Some(g) => g,
            None => {
                eprintln!("ERROR: invalid GUID format");
                return Status::Unsuccessful;
            }
        };

        let wide_name = to_wide(name);
        let us_name = make_unicode_string(&wide_name);
        // EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
        let attributes: u32 = 0x00000007;

        unsafe {
            let func: NtSetSystemEnvironmentValueExFn = match get_ntdll_proc(
                c"NtSetSystemEnvironmentValueEx",
            ) {
                Some(f) => f,
                None => {
                    eprintln!("ERROR: Could not find NtSetSystemEnvironmentValueEx in ntdll");
                    return Status::Unsuccessful;
                }
            };

            // Delete by setting with null value and zero length
            let status = func(
                &us_name,
                &guid,
                std::ptr::null(),
                0,
                attributes,
            );
            if status < 0 {
                eprintln!("ERROR: NtSetSystemEnvironmentValueEx(delete): NTSTATUS 0x{:08x}", status as u32);
                return Status::Unsuccessful;
            }

            println!("NtSetSystemEnvironmentValueEx(delete \"{}\") : OK !", name);
        }
        Status::Success
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod win {
    use crate::module::Status;

    fn not_windows(name: &str) -> Status {
        eprintln!("ERROR: sysenv::{} requires Windows", name);
        Status::Unsuccessful
    }

    pub fn cmd_list(_args: &[String]) -> Status { not_windows("list") }
    pub fn cmd_get(_args: &[String]) -> Status { not_windows("get") }
    pub fn cmd_set(_args: &[String]) -> Status { not_windows("set") }
    pub fn cmd_del(_args: &[String]) -> Status { not_windows("del") }
}

// ---------------------------------------------------------------------------
// Dispatch to platform-specific implementations
// ---------------------------------------------------------------------------

fn cmd_list(args: &[String]) -> Status { win::cmd_list(args) }
fn cmd_get(args: &[String]) -> Status { win::cmd_get(args) }
fn cmd_set(args: &[String]) -> Status { win::cmd_set(args) }
fn cmd_del(args: &[String]) -> Status { win::cmd_del(args) }
