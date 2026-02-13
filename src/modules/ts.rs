//! Terminal Server module -- RDP session enumeration and management.
//!
//! Provides commands for listing Terminal Services / RDP sessions,
//! enabling multiple concurrent RDP connections, and toggling remote
//! desktop access via the registry.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
#[cfg(windows)]
use crate::display;

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "ts",
    full_name: "Terminal Server module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 4] = [
    Command { name: "sessions",       description: "List TS/RDP sessions",     handler: cmd_sessions },
    Command { name: "multirdp",       description: "Enable or disable multiple RDP connections", handler: cmd_multirdp },
    Command { name: "remote",         description: "Allow remote connection",  handler: cmd_remote },
    Command { name: "logonpasswords", description: "List TS credentials",      handler: cmd_logonpasswords },
];

// ===========================================================================
// ts::sessions -- Enumerate Terminal Services sessions (Windows only)
// ===========================================================================

fn cmd_sessions(args: &[String]) -> Status {
    let _ = args;

    #[cfg(windows)]
    {
        use windows::Win32::System::LibraryLoader::*;
        use windows::core::PCWSTR;

        println!("\nEnumerating Terminal Services sessions...\n");

        // Dynamic loading of wtsapi32.dll for WTSEnumerateSessionsW
        // and WTSQuerySessionInformationW.
        //
        // We use dynamic loading because the WTS functions may not be
        // available through the windows crate features we've enabled.

        type FnWtsEnumerateSessionsW = unsafe extern "system" fn(
            hserver: isize,      // HANDLE
            reserved: u32,
            version: u32,
            ppsessioninfo: *mut *mut WtsSessionInfoW,
            pcount: *mut u32,
        ) -> i32;

        type FnWtsFreeMemory = unsafe extern "system" fn(pmemory: *mut std::ffi::c_void);

        type FnWtsQuerySessionInformationW = unsafe extern "system" fn(
            hserver: isize,
            sessionid: u32,
            wtsinfoclass: u32,
            ppbuffer: *mut *mut u16,
            pbytesreturned: *mut u32,
        ) -> i32;

        #[repr(C)]
        struct WtsSessionInfoW {
            session_id: u32,
            win_station_name: *const u16,
            state: u32,
        }

        // WTS_CURRENT_SERVER_HANDLE
        const WTS_CURRENT_SERVER_HANDLE: isize = 0;
        // WTSInfoClass: WTSUserName = 5, WTSDomainName = 7
        const WTS_USER_NAME: u32 = 5;
        const WTS_DOMAIN_NAME: u32 = 7;

        let state_names = [
            "Active", "Connected", "ConnectQuery", "Shadow", "Disconnected",
            "Idle", "Listen", "Reset", "Down", "Init",
        ];

        unsafe {
            let dll_name: Vec<u16> = "wtsapi32.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let lib = match LoadLibraryW(PCWSTR(dll_name.as_ptr())) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ERROR: LoadLibraryW(wtsapi32.dll): {}", e);
                    return Status::Unsuccessful;
                }
            };

            let fn_enumerate: FnWtsEnumerateSessionsW = match GetProcAddress(lib, windows::core::s!("WTSEnumerateSessionsW")) {
                Some(p) => std::mem::transmute(p),
                None => {
                    eprintln!("ERROR: GetProcAddress(WTSEnumerateSessionsW) failed");
                    return Status::Unsuccessful;
                }
            };

            let fn_free: FnWtsFreeMemory = match GetProcAddress(lib, windows::core::s!("WTSFreeMemory")) {
                Some(p) => std::mem::transmute(p),
                None => {
                    eprintln!("ERROR: GetProcAddress(WTSFreeMemory) failed");
                    return Status::Unsuccessful;
                }
            };

            let fn_query: FnWtsQuerySessionInformationW = match GetProcAddress(lib, windows::core::s!("WTSQuerySessionInformationW")) {
                Some(p) => std::mem::transmute(p),
                None => {
                    eprintln!("ERROR: GetProcAddress(WTSQuerySessionInformationW) failed");
                    return Status::Unsuccessful;
                }
            };

            let mut session_info: *mut WtsSessionInfoW = std::ptr::null_mut();
            let mut count: u32 = 0;

            let result = fn_enumerate(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1, // version must be 1
                &mut session_info,
                &mut count,
            );

            if result == 0 {
                eprintln!("ERROR: WTSEnumerateSessionsW failed");
                return Status::Unsuccessful;
            }

            println!("{:<6} {:<20} {:<15} {:<20} {:<20}", "ID", "Station", "State", "User", "Domain");
            println!("{}", "-".repeat(81));

            for i in 0..count as isize {
                let info = &*session_info.offset(i);
                let session_id = info.session_id;

                // Read station name
                let station_name = if !info.win_station_name.is_null() {
                    let mut len = 0;
                    while *info.win_station_name.add(len) != 0 { len += 1; }
                    let slice = std::slice::from_raw_parts(info.win_station_name, len);
                    String::from_utf16_lossy(slice)
                } else {
                    String::new()
                };

                let state_str = if (info.state as usize) < state_names.len() {
                    state_names[info.state as usize]
                } else {
                    "Unknown"
                };

                // Query user name
                let mut user_buf: *mut u16 = std::ptr::null_mut();
                let mut user_len: u32 = 0;
                let mut username = String::new();
                if fn_query(WTS_CURRENT_SERVER_HANDLE, session_id, WTS_USER_NAME, &mut user_buf, &mut user_len) != 0 {
                    if !user_buf.is_null() && user_len > 0 {
                        let chars = user_len as usize / 2;
                        let slice = std::slice::from_raw_parts(user_buf, chars);
                        username = String::from_utf16_lossy(slice);
                        username = username.trim_end_matches('\0').to_string();
                    }
                    if !user_buf.is_null() { fn_free(user_buf as *mut _); }
                }

                // Query domain name
                let mut domain_buf: *mut u16 = std::ptr::null_mut();
                let mut domain_len: u32 = 0;
                let mut domain = String::new();
                if fn_query(WTS_CURRENT_SERVER_HANDLE, session_id, WTS_DOMAIN_NAME, &mut domain_buf, &mut domain_len) != 0 {
                    if !domain_buf.is_null() && domain_len > 0 {
                        let chars = domain_len as usize / 2;
                        let slice = std::slice::from_raw_parts(domain_buf, chars);
                        domain = String::from_utf16_lossy(slice);
                        domain = domain.trim_end_matches('\0').to_string();
                    }
                    if !domain_buf.is_null() { fn_free(domain_buf as *mut _); }
                }

                println!("{:<6} {:<20} {:<15} {:<20} {:<20}", session_id, station_name, state_str, username, domain);
            }

            fn_free(session_info as *mut _);
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        eprintln!("ERROR: ts::sessions requires Windows (WTS API)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// ts::multirdp -- Stub (termsrv.dll memory patch)
// ===========================================================================

fn cmd_multirdp(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ts::multirdp not yet implemented");
    eprintln!("  This command patches termsrv.dll in memory to allow multiple");
    eprintln!("  concurrent RDP sessions on Windows workstation editions.");
    eprintln!("  Requires:");
    eprintln!("    - Finding termsrv.dll in svchost.exe (TermService)");
    eprintln!("    - Locating the single-session check byte pattern");
    eprintln!("    - Patching the conditional jump to always allow connections");
    eprintln!("    - The patch pattern varies by Windows version");
    Status::Unsuccessful
}

// ===========================================================================
// ts::remote -- Enable/disable Remote Desktop via registry
// ===========================================================================

fn cmd_remote(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let enable = display::has_named_flag(args, "enable");
        let disable = display::has_named_flag(args, "disable");

        if !enable && !disable {
            eprintln!("ERROR: /enable or /disable flag required");
            eprintln!("  Usage: ts::remote /enable");
            eprintln!("         ts::remote /disable");
            return Status::Unsuccessful;
        }

        let value = if enable { 0u32 } else { 1u32 };
        let action = if enable { "Enabling" } else { "Disabling" };

        println!("\n{} Remote Desktop connections...", action);
        println!("  Key  : HKLM\\System\\CurrentControlSet\\Control\\Terminal Server");
        println!("  Value: fDenyTSConnections = {}", value);

        // Use the same registry helper pattern as misc module
        use windows::Win32::System::Registry::*;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::core::PCWSTR;

        let subkey = "System\\CurrentControlSet\\Control\\Terminal Server";
        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let value_name = "fDenyTSConnections";
        let value_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut key = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_wide.as_ptr()),
                0,
                KEY_WRITE,
                &mut key,
            );
            if status != ERROR_SUCCESS {
                eprintln!("ERROR: RegOpenKeyExW: {:?}", status);
                eprintln!("  (Requires elevation / administrator privileges)");
                return Status::Unsuccessful;
            }

            let data_bytes = value.to_le_bytes();
            let status = RegSetValueExW(
                key,
                PCWSTR(value_wide.as_ptr()),
                0,
                REG_DWORD,
                Some(&data_bytes),
            );

            let _ = RegCloseKey(key);

            if status == ERROR_SUCCESS {
                println!("  Done. Remote Desktop is now {}.", if enable { "enabled" } else { "disabled" });
                return Status::Success;
            } else {
                eprintln!("ERROR: RegSetValueExW: {:?}", status);
                return Status::Unsuccessful;
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: ts::remote requires Windows (registry access)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// ts::logonpasswords -- Stub (TS package credential extraction)
// ===========================================================================

fn cmd_logonpasswords(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: ts::logonpasswords not yet implemented");
    eprintln!("  This command extracts Terminal Services credentials from LSASS memory,");
    eprintln!("  specifically from the TsPkg (msvtsp.dll) security package.");
    eprintln!("  Requires the same LSASS memory reading infrastructure as sekurlsa.");
    eprintln!("  Use 'sekurlsa::tspkg' instead for now.");
    Status::Unsuccessful
}
