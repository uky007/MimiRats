//! Net module -- Network user, group, session, and time-of-day enumeration.
//!
//! Uses the NetAPI32 family of functions (Windows only) to query information
//! from local or remote servers: users, groups, aliases, sessions, workstation
//! sessions, and remote time of day.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
use crate::display;

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "net",
    full_name: "Net module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 6] = [
    Command { name: "user",     description: "List local users",              handler: cmd_user },
    Command { name: "group",    description: "List local groups",             handler: cmd_group },
    Command { name: "alias",    description: "List aliases (groups)",         handler: cmd_alias },
    Command { name: "session",  description: "List sessions",                handler: cmd_session },
    Command { name: "wsession", description: "List workstation sessions",    handler: cmd_wsession },
    Command { name: "tod",      description: "Display time of day",          handler: cmd_tod },
];

// ===========================================================================
// Helper: extract server name from args
// ===========================================================================

/// Extract optional `/server:\\name` argument. Returns None for local machine.
fn get_server_name(args: &[String]) -> Option<String> {
    display::find_named_arg(args, "server").map(|s| s.to_string())
}

/// Convert a Rust string to a null-terminated wide (UTF-16) string for Win32 APIs.
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ===========================================================================
// Windows implementation using dynamic loading of netapi32.dll
// ===========================================================================

#[cfg(windows)]
mod netapi {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::LibraryLoader::*;
    use windows::core::PCWSTR;

    /// Dynamically loaded function pointer types for NetAPI32.dll.
    /// We use dynamic loading because the specific function bindings
    /// may not be available in the windows crate features we've enabled.

    type FnNetApiBufferFree = unsafe extern "system" fn(buffer: *mut std::ffi::c_void) -> u32;
    type FnNetUserEnum = unsafe extern "system" fn(
        servername: *const u16,
        level: u32,
        filter: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
    type FnNetGroupEnum = unsafe extern "system" fn(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
    type FnNetLocalGroupEnum = unsafe extern "system" fn(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
    type FnNetSessionEnum = unsafe extern "system" fn(
        servername: *const u16,
        unclientname: *const u16,
        username: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
    type FnNetWkstaUserEnum = unsafe extern "system" fn(
        servername: *const u16,
        level: u32,
        bufptr: *mut *mut u8,
        prefmaxlen: u32,
        entriesread: *mut u32,
        totalentries: *mut u32,
        resume_handle: *mut u32,
    ) -> u32;
    type FnNetRemoteTOD = unsafe extern "system" fn(
        uncservername: *const u16,
        bufptr: *mut *mut u8,
    ) -> u32;

    /// Cached handle to netapi32.dll and resolved function pointers.
    pub struct NetApi {
        _lib: HMODULE,
        pub net_api_buffer_free: FnNetApiBufferFree,
        pub net_user_enum: FnNetUserEnum,
        pub net_group_enum: FnNetGroupEnum,
        pub net_local_group_enum: FnNetLocalGroupEnum,
        pub net_session_enum: FnNetSessionEnum,
        pub net_wksta_user_enum: FnNetWkstaUserEnum,
        pub net_remote_tod: FnNetRemoteTOD,
    }

    impl NetApi {
        /// Load netapi32.dll and resolve all required function pointers.
        pub fn load() -> Result<Self, String> {
            unsafe {
                let dll_name = super::to_wide("netapi32.dll");
                let lib = LoadLibraryW(PCWSTR(dll_name.as_ptr()))
                    .map_err(|e| format!("LoadLibraryW(netapi32.dll): {}", e))?;

                macro_rules! resolve {
                    ($name:expr) => {{
                        let proc = GetProcAddress(lib, windows::core::s!($name));
                        match proc {
                            Some(p) => std::mem::transmute(p),
                            None => return Err(format!("GetProcAddress({}) failed", $name)),
                        }
                    }};
                }

                Ok(NetApi {
                    _lib: lib,
                    net_api_buffer_free: resolve!("NetApiBufferFree"),
                    net_user_enum: resolve!("NetUserEnum"),
                    net_group_enum: resolve!("NetGroupEnum"),
                    net_local_group_enum: resolve!("NetLocalGroupEnum"),
                    net_session_enum: resolve!("NetSessionEnum"),
                    net_wksta_user_enum: resolve!("NetWkstaUserEnum"),
                    net_remote_tod: resolve!("NetRemoteTOD"),
                })
            }
        }
    }

    // Win32 NERR_Success
    pub const NERR_SUCCESS: u32 = 0;
    // MAX_PREFERRED_LENGTH
    pub const MAX_PREFERRED_LENGTH: u32 = 0xFFFFFFFF;

    /// USER_INFO_0: just the username pointer (LPWSTR).
    #[repr(C)]
    pub struct UserInfo0 {
        pub usri0_name: *const u16,
    }

    /// GROUP_INFO_0: just the group name pointer.
    #[repr(C)]
    pub struct GroupInfo0 {
        pub grpi0_name: *const u16,
    }

    /// LOCALGROUP_INFO_0: just the alias name pointer.
    #[repr(C)]
    pub struct LocalGroupInfo0 {
        pub lgrpi0_name: *const u16,
    }

    /// SESSION_INFO_10: client name, username, time, idle_time.
    #[repr(C)]
    pub struct SessionInfo10 {
        pub sesi10_cname: *const u16,
        pub sesi10_username: *const u16,
        pub sesi10_time: u32,
        pub sesi10_idle_time: u32,
    }

    /// WKSTA_USER_INFO_0: username.
    #[repr(C)]
    pub struct WkstaUserInfo0 {
        pub wkui0_username: *const u16,
    }

    /// TIME_OF_DAY_INFO
    #[repr(C)]
    pub struct TimeOfDayInfo {
        pub tod_elapsedt: u32,
        pub tod_msecs: u32,
        pub tod_hours: u32,
        pub tod_mins: u32,
        pub tod_secs: u32,
        pub tod_hunds: u32,
        pub tod_timezone: i32,
        pub tod_tinterval: u32,
        pub tod_day: u32,
        pub tod_month: u32,
        pub tod_year: u32,
        pub tod_weekday: u32,
    }

    /// Read a null-terminated UTF-16 string from a raw pointer.
    pub unsafe fn read_wide_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

// ===========================================================================
// net::user
// ===========================================================================

fn cmd_user(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let server = get_server_name(args);
        let server_wide = server.as_ref().map(|s| to_wide(s));
        let server_ptr = server_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

        let api = match netapi::NetApi::load() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        };

        println!("\nUser accounts for {}:\n", server.as_deref().unwrap_or("\\\\localhost"));
        println!("{:<40} {}", "User name", "Comment");
        println!("{}", "-".repeat(60));

        unsafe {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume: u32 = 0;

            let status = (api.net_user_enum)(
                server_ptr,
                0, // level 0 = USER_INFO_0 (names only)
                0, // filter: all users
                &mut buf,
                netapi::MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            );

            if status == netapi::NERR_SUCCESS && !buf.is_null() {
                let entries = buf as *const netapi::UserInfo0;
                for i in 0..entries_read as usize {
                    let entry = &*entries.add(i);
                    let name = netapi::read_wide_string(entry.usri0_name);
                    println!("{:<40}", name);
                }
                println!("\nTotal entries: {}", total_entries);
                (api.net_api_buffer_free)(buf as *mut _);
            } else {
                eprintln!("ERROR: NetUserEnum failed with status {}", status);
                if !buf.is_null() {
                    (api.net_api_buffer_free)(buf as *mut _);
                }
                return Status::Unsuccessful;
            }
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: net::user requires Windows (NetAPI32)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// net::group
// ===========================================================================

fn cmd_group(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let server = get_server_name(args);
        let server_wide = server.as_ref().map(|s| to_wide(s));
        let server_ptr = server_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

        let api = match netapi::NetApi::load() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        };

        println!("\nGroup accounts for {}:\n", server.as_deref().unwrap_or("\\\\localhost"));
        println!("{:<40}", "Group name");
        println!("{}", "-".repeat(40));

        unsafe {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume: u32 = 0;

            let status = (api.net_group_enum)(
                server_ptr,
                0,
                &mut buf,
                netapi::MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            );

            if status == netapi::NERR_SUCCESS && !buf.is_null() {
                let entries = buf as *const netapi::GroupInfo0;
                for i in 0..entries_read as usize {
                    let entry = &*entries.add(i);
                    let name = netapi::read_wide_string(entry.grpi0_name);
                    println!("{:<40}", name);
                }
                println!("\nTotal entries: {}", total_entries);
                (api.net_api_buffer_free)(buf as *mut _);
            } else {
                eprintln!("ERROR: NetGroupEnum failed with status {}", status);
                if !buf.is_null() {
                    (api.net_api_buffer_free)(buf as *mut _);
                }
                return Status::Unsuccessful;
            }
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: net::group requires Windows (NetAPI32)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// net::alias
// ===========================================================================

fn cmd_alias(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let server = get_server_name(args);
        let server_wide = server.as_ref().map(|s| to_wide(s));
        let server_ptr = server_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

        let api = match netapi::NetApi::load() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        };

        println!("\nAliases (local groups) for {}:\n", server.as_deref().unwrap_or("\\\\localhost"));
        println!("{:<40}", "Alias name");
        println!("{}", "-".repeat(40));

        unsafe {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume: u32 = 0;

            let status = (api.net_local_group_enum)(
                server_ptr,
                0,
                &mut buf,
                netapi::MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            );

            if status == netapi::NERR_SUCCESS && !buf.is_null() {
                let entries = buf as *const netapi::LocalGroupInfo0;
                for i in 0..entries_read as usize {
                    let entry = &*entries.add(i);
                    let name = netapi::read_wide_string(entry.lgrpi0_name);
                    println!("{:<40}", name);
                }
                println!("\nTotal entries: {}", total_entries);
                (api.net_api_buffer_free)(buf as *mut _);
            } else {
                eprintln!("ERROR: NetLocalGroupEnum failed with status {}", status);
                if !buf.is_null() {
                    (api.net_api_buffer_free)(buf as *mut _);
                }
                return Status::Unsuccessful;
            }
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: net::alias requires Windows (NetAPI32)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// net::session
// ===========================================================================

fn cmd_session(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let server = get_server_name(args);
        let server_wide = server.as_ref().map(|s| to_wide(s));
        let server_ptr = server_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

        let api = match netapi::NetApi::load() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        };

        println!("\nSessions for {}:\n", server.as_deref().unwrap_or("\\\\localhost"));
        println!("{:<30} {:<20} {:>10} {:>10}", "Client", "User", "Time", "Idle");
        println!("{}", "-".repeat(74));

        unsafe {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume: u32 = 0;

            let status = (api.net_session_enum)(
                server_ptr,
                std::ptr::null(), // no client filter
                std::ptr::null(), // no user filter
                10,               // level 10 = SESSION_INFO_10
                &mut buf,
                netapi::MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            );

            if status == netapi::NERR_SUCCESS && !buf.is_null() {
                let entries = buf as *const netapi::SessionInfo10;
                for i in 0..entries_read as usize {
                    let entry = &*entries.add(i);
                    let client = netapi::read_wide_string(entry.sesi10_cname);
                    let user = netapi::read_wide_string(entry.sesi10_username);
                    println!(
                        "{:<30} {:<20} {:>10} {:>10}",
                        client, user, entry.sesi10_time, entry.sesi10_idle_time
                    );
                }
                println!("\nTotal entries: {}", total_entries);
                (api.net_api_buffer_free)(buf as *mut _);
            } else {
                eprintln!("ERROR: NetSessionEnum failed with status {}", status);
                if !buf.is_null() {
                    (api.net_api_buffer_free)(buf as *mut _);
                }
                return Status::Unsuccessful;
            }
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: net::session requires Windows (NetAPI32)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// net::wsession
// ===========================================================================

fn cmd_wsession(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let server = get_server_name(args);
        let server_wide = server.as_ref().map(|s| to_wide(s));
        let server_ptr = server_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

        let api = match netapi::NetApi::load() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        };

        println!("\nWorkstation sessions for {}:\n", server.as_deref().unwrap_or("\\\\localhost"));
        println!("{:<40}", "User name");
        println!("{}", "-".repeat(40));

        unsafe {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut entries_read: u32 = 0;
            let mut total_entries: u32 = 0;
            let mut resume: u32 = 0;

            let status = (api.net_wksta_user_enum)(
                server_ptr,
                0, // level 0 = WKSTA_USER_INFO_0
                &mut buf,
                netapi::MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            );

            if status == netapi::NERR_SUCCESS && !buf.is_null() {
                let entries = buf as *const netapi::WkstaUserInfo0;
                for i in 0..entries_read as usize {
                    let entry = &*entries.add(i);
                    let name = netapi::read_wide_string(entry.wkui0_username);
                    println!("{:<40}", name);
                }
                println!("\nTotal entries: {}", total_entries);
                (api.net_api_buffer_free)(buf as *mut _);
            } else {
                eprintln!("ERROR: NetWkstaUserEnum failed with status {}", status);
                if !buf.is_null() {
                    (api.net_api_buffer_free)(buf as *mut _);
                }
                return Status::Unsuccessful;
            }
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: net::wsession requires Windows (NetAPI32)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// net::tod
// ===========================================================================

fn cmd_tod(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let server = get_server_name(args);
        let server_wide = server.as_ref().map(|s| to_wide(s));
        let server_ptr = server_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());

        let api = match netapi::NetApi::load() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        };

        println!("\nTime of day for {}:\n", server.as_deref().unwrap_or("\\\\localhost"));

        unsafe {
            let mut buf: *mut u8 = std::ptr::null_mut();

            let status = (api.net_remote_tod)(
                server_ptr,
                &mut buf,
            );

            if status == netapi::NERR_SUCCESS && !buf.is_null() {
                let tod = &*(buf as *const netapi::TimeOfDayInfo);
                println!(
                    "  Date     : {:04}/{:02}/{:02}",
                    tod.tod_year, tod.tod_month, tod.tod_day
                );
                println!(
                    "  Time     : {:02}:{:02}:{:02}.{:02}",
                    tod.tod_hours, tod.tod_mins, tod.tod_secs, tod.tod_hunds
                );
                println!("  Timezone : {} minutes from GMT", tod.tod_timezone);
                println!("  Elapsed  : {} seconds since boot", tod.tod_elapsedt);
                (api.net_api_buffer_free)(buf as *mut _);
            } else {
                eprintln!("ERROR: NetRemoteTOD failed with status {}", status);
                if !buf.is_null() {
                    (api.net_api_buffer_free)(buf as *mut _);
                }
                return Status::Unsuccessful;
            }
        }

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: net::tod requires Windows (NetAPI32)");
        Status::Unsuccessful
    }
}
