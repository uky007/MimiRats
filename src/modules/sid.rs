//! SID module — Security Identifier lookup and manipulation.
//!
//! Resolves account names to SIDs and vice versa using
//! `LookupAccountNameW` / `LookupAccountSidW`.

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "sid",
    full_name: "Security Identifiers module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 4] = [
    Command {
        name: "lookup",
        description: "Name or SID lookup",
        handler: cmd_lookup,
    },
    Command {
        name: "query",
        description: "Query object by SID or name",
        handler: cmd_query,
    },
    Command {
        name: "modify",
        description: "Modify object SID of an object",
        handler: cmd_modify,
    },
    Command {
        name: "add",
        description: "Add a SID to sIDHistory of an object",
        handler: cmd_add,
    },
];

// ---------------------------------------------------------------------------
// Windows implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_lookup(args: &[String]) -> Status {
    use crate::display::find_named_arg;
    use windows::Win32::Security::*;
    use windows::Win32::Foundation::*;
    use windows::core::*;

    let name_arg = find_named_arg(args, "name");
    let sid_arg = find_named_arg(args, "sid");

    if name_arg.is_none() && sid_arg.is_none() {
        eprintln!("ERROR: provide /name:AccountName or /sid:S-1-5-...");
        return Status::Unsuccessful;
    }

    if let Some(account_name) = name_arg {
        // LookupAccountNameW: name -> SID
        let wide_name: Vec<u16> = account_name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // First call: get buffer sizes
            let mut sid_size: u32 = 0;
            let mut domain_size: u32 = 0;
            let mut sid_type = SID_NAME_USE::default();

            let _ = LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(wide_name.as_ptr()),
                PSID::default(),
                &mut sid_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_type,
            );

            if sid_size == 0 {
                eprintln!("ERROR: LookupAccountNameW: account \"{}\" not found", account_name);
                return Status::Unsuccessful;
            }

            // Second call: get actual data
            let mut sid_buf = vec![0u8; sid_size as usize];
            let mut domain_buf = vec![0u16; domain_size as usize];

            match LookupAccountNameW(
                PCWSTR::null(),
                PCWSTR(wide_name.as_ptr()),
                PSID(sid_buf.as_mut_ptr() as *mut _),
                &mut sid_size,
                PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_size,
                &mut sid_type,
            ) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("ERROR: LookupAccountNameW: {}", e);
                    return Status::Unsuccessful;
                }
            }

            let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);
            let sid_str = crate::display::format_sid(&sid_buf[..sid_size as usize]);

            println!("Account  : {}", account_name);
            println!("Domain   : {}", domain);
            println!("SID      : {}", sid_str);
            println!("Type     : {} ({})", sid_name_use_str(sid_type), sid_type.0);
        }
        return Status::Success;
    }

    if let Some(sid_string) = sid_arg {
        // ConvertStringSidToSidW + LookupAccountSidW: SID string -> name
        let wide_sid: Vec<u16> = sid_string.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Convert string SID to binary SID
            // Try using ConvertStringSidToSidW via dynamic load from Advapi32
            type ConvertStringSidToSidWFn = unsafe extern "system" fn(
                string_sid: PCWSTR,
                sid: *mut PSID,
            ) -> BOOL;
            type LocalFreeFn = unsafe extern "system" fn(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;

            let advapi32 = windows::Win32::System::LibraryLoader::GetModuleHandleW(w!("advapi32.dll"));
            let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleW(w!("kernel32.dll"));

            let (advapi32_h, kernel32_h) = match (advapi32, kernel32) {
                (Ok(a), Ok(k)) => (a, k),
                _ => {
                    eprintln!("ERROR: Could not load advapi32.dll or kernel32.dll");
                    return Status::Unsuccessful;
                }
            };

            let convert_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
                advapi32_h,
                PCSTR(c"ConvertStringSidToSidW".as_ptr() as *const u8),
            );
            let local_free_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
                kernel32_h,
                PCSTR(c"LocalFree".as_ptr() as *const u8),
            );

            let (convert_fn, local_free_fn) = match (convert_fn, local_free_fn) {
                (Some(c), Some(l)) => (c, l),
                _ => {
                    eprintln!("ERROR: Could not find ConvertStringSidToSidW or LocalFree");
                    return Status::Unsuccessful;
                }
            };

            let convert: ConvertStringSidToSidWFn = std::mem::transmute(convert_fn);
            let local_free: LocalFreeFn = std::mem::transmute(local_free_fn);

            let mut psid = PSID::default();
            let result = convert(PCWSTR(wide_sid.as_ptr()), &mut psid);
            if !result.as_bool() {
                eprintln!("ERROR: ConvertStringSidToSidW failed for \"{}\"", sid_string);
                return Status::Unsuccessful;
            }

            // LookupAccountSidW
            let mut name_size: u32 = 0;
            let mut domain_size: u32 = 0;
            let mut sid_type = SID_NAME_USE::default();

            let _ = LookupAccountSidW(
                PCWSTR::null(),
                psid,
                PWSTR::null(),
                &mut name_size,
                PWSTR::null(),
                &mut domain_size,
                &mut sid_type,
            );

            if name_size == 0 && domain_size == 0 {
                eprintln!("ERROR: LookupAccountSidW: SID \"{}\" not found", sid_string);
                local_free(psid.0);
                return Status::Unsuccessful;
            }

            let mut name_buf = vec![0u16; name_size as usize];
            let mut domain_buf = vec![0u16; domain_size as usize];

            match LookupAccountSidW(
                PCWSTR::null(),
                psid,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_size,
                PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_size,
                &mut sid_type,
            ) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("ERROR: LookupAccountSidW: {}", e);
                    local_free(psid.0);
                    return Status::Unsuccessful;
                }
            }

            let name = String::from_utf16_lossy(&name_buf[..name_size as usize]);
            let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);

            println!("SID      : {}", sid_string);
            println!("Domain   : {}", domain);
            println!("Account  : {}", name);
            println!("Type     : {} ({})", sid_name_use_str(sid_type), sid_type.0);

            local_free(psid.0);
        }
        return Status::Success;
    }

    Status::Unsuccessful
}

#[cfg(windows)]
fn sid_name_use_str(t: windows::Win32::Security::SID_NAME_USE) -> &'static str {
    use windows::Win32::Security::*;
    match t {
        SidTypeUser => "User",
        SidTypeGroup => "Group",
        SidTypeDomain => "Domain",
        SidTypeAlias => "Alias",
        SidTypeWellKnownGroup => "WellKnownGroup",
        SidTypeDeletedAccount => "DeletedAccount",
        SidTypeInvalid => "Invalid",
        SidTypeUnknown => "Unknown",
        SidTypeComputer => "Computer",
        SidTypeLabel => "Label",
        SidTypeLogonSession => "LogonSession",
        _ => "(?)",
    }
}

#[cfg(not(windows))]
fn cmd_lookup(_args: &[String]) -> Status {
    eprintln!("ERROR: sid::lookup requires Windows");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// Stubs — require LDAP / NTDS access, not yet implemented
// ---------------------------------------------------------------------------

fn cmd_query(_args: &[String]) -> Status {
    eprintln!("ERROR: sid::query not yet implemented");
    eprintln!("       This command requires LDAP access to query objects by SID or name.");
    Status::Unsuccessful
}

fn cmd_modify(_args: &[String]) -> Status {
    eprintln!("ERROR: sid::modify not yet implemented");
    eprintln!("       This command requires LDAP access and NTDS patching to modify object SIDs.");
    Status::Unsuccessful
}

fn cmd_add(_args: &[String]) -> Status {
    eprintln!("ERROR: sid::add not yet implemented");
    eprintln!("       This command requires LDAP access to add SIDs to sIDHistory.");
    Status::Unsuccessful
}
