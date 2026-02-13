//! Miscellaneous module -- GPO bypass, memory patching stubs, compression.
//!
//! Provides commands to disable Group Policy restrictions (DisableCMD,
//! DisableRegistryTools, DisableTaskMgr) by modifying the relevant
//! registry values, plus stubs for LSASS patching operations.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
use crate::display;

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "misc",
    full_name: "Miscellaneous module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 8] = [
    Command { name: "cmd",        description: "Command Prompt (without DisableCMD)",                handler: cmd_cmd },
    Command { name: "regedit",    description: "Registry Editor (without DisableRegistryTools)",     handler: cmd_regedit },
    Command { name: "taskmgr",    description: "Task Manager (without DisableTaskMgr)",              handler: cmd_taskmgr },
    Command { name: "ncroutemon", description: "Juniper Network Connect (without route monitoring)", handler: cmd_ncroutemon },
    Command { name: "detours",    description: "List or start processes with Microsoft Detours",     handler: cmd_detours },
    Command { name: "memssp",     description: "Patch LSASS for SSP",                               handler: cmd_memssp },
    Command { name: "skeleton",   description: "Patch Domain Controller for Skeleton Key",           handler: cmd_skeleton },
    Command { name: "compress",   description: "Compress a file with a NT6 function",                handler: cmd_compress },
];

// ===========================================================================
// Registry helper: set a DWORD value
// ===========================================================================

/// Set a DWORD registry value (Windows only).
#[cfg(windows)]
fn reg_set_dword(hive_name: &str, subkey: &str, value_name: &str, data: u32) -> Result<(), String> {
    use windows::Win32::System::Registry::*;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::core::PCWSTR;

    let hive = match hive_name {
        "HKCU" => HKEY_CURRENT_USER,
        "HKLM" => HKEY_LOCAL_MACHINE,
        _ => return Err(format!("Unknown hive: {}", hive_name)),
    };

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut key = HKEY::default();
        // Open with write access; create the key path if it doesn't exist.
        let status = RegCreateKeyExW(
            hive,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        );
        if status != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW({}\\{}): {:?}", hive_name, subkey, status));
        }

        let data_bytes = data.to_le_bytes();
        let status = RegSetValueExW(
            key,
            PCWSTR(value_wide.as_ptr()),
            0,
            REG_DWORD,
            Some(&data_bytes),
        );

        let _ = RegCloseKey(key);

        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW({}, {}): {:?}", subkey, value_name, status));
        }
    }

    Ok(())
}

// ===========================================================================
// misc::cmd -- Disable DisableCMD GPO
// ===========================================================================

fn cmd_cmd(args: &[String]) -> Status {
    let _ = args;

    #[cfg(windows)]
    {
        println!("\nDisabling DisableCMD GPO restriction...");
        println!("  Key  : HKCU\\Software\\Policies\\Microsoft\\Windows\\System");
        println!("  Value: DisableCMD = 0");

        match reg_set_dword(
            "HKCU",
            "Software\\Policies\\Microsoft\\Windows\\System",
            "DisableCMD",
            0,
        ) {
            Ok(()) => {
                println!("  Done. Command Prompt should now be accessible.");
                return Status::Success;
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("ERROR: misc::cmd requires Windows (registry access)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// misc::regedit -- Disable DisableRegistryTools GPO
// ===========================================================================

fn cmd_regedit(args: &[String]) -> Status {
    let _ = args;

    #[cfg(windows)]
    {
        println!("\nDisabling DisableRegistryTools GPO restriction...");
        println!("  Key  : HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        println!("  Value: DisableRegistryTools = 0");

        match reg_set_dword(
            "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "DisableRegistryTools",
            0,
        ) {
            Ok(()) => {
                println!("  Done. Registry Editor should now be accessible.");
                return Status::Success;
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("ERROR: misc::regedit requires Windows (registry access)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// misc::taskmgr -- Disable DisableTaskMgr GPO
// ===========================================================================

fn cmd_taskmgr(args: &[String]) -> Status {
    let _ = args;

    #[cfg(windows)]
    {
        println!("\nDisabling DisableTaskMgr GPO restriction...");
        println!("  Key  : HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        println!("  Value: DisableTaskMgr = 0");

        match reg_set_dword(
            "HKCU",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "DisableTaskMgr",
            0,
        ) {
            Ok(()) => {
                println!("  Done. Task Manager should now be accessible.");
                return Status::Success;
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                return Status::Unsuccessful;
            }
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("ERROR: misc::taskmgr requires Windows (registry access)");
        Status::Unsuccessful
    }
}

// ===========================================================================
// misc::ncroutemon -- Stub
// ===========================================================================

fn cmd_ncroutemon(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: misc::ncroutemon not yet implemented");
    eprintln!("  This command disables Juniper Network Connect route monitoring");
    eprintln!("  by patching the dsNcService.exe process in memory.");
    eprintln!("  Requires: process memory patching of the route monitoring check.");
    Status::Unsuccessful
}

// ===========================================================================
// misc::detours -- Stub
// ===========================================================================

fn cmd_detours(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: misc::detours not yet implemented");
    eprintln!("  This command lists processes that have Microsoft Detours loaded,");
    eprintln!("  or starts a new process with a Detours DLL injected.");
    eprintln!("  Requires: PE header analysis and CreateProcessW with DLL injection.");
    Status::Unsuccessful
}

// ===========================================================================
// misc::memssp -- Stub (LSASS SSP memory patch)
// ===========================================================================

fn cmd_memssp(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: misc::memssp not yet implemented");
    eprintln!("  This command patches the msv1_0.dll SSP in LSASS memory to log");
    eprintln!("  plaintext credentials to a file (C:\\Windows\\System32\\mimilsa.log).");
    eprintln!("  Requires:");
    eprintln!("    - SeDebugPrivilege");
    eprintln!("    - Opening LSASS with PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION");
    eprintln!("    - Finding msv1_0.dll's SpAcceptCredentials function");
    eprintln!("    - Allocating memory in LSASS and writing a hook trampoline");
    eprintln!("    - Patching the function pointer to redirect to the hook");
    Status::Unsuccessful
}

// ===========================================================================
// misc::skeleton -- Stub (DC Skeleton Key patch)
// ===========================================================================

fn cmd_skeleton(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: misc::skeleton not yet implemented");
    eprintln!("  This command patches the Domain Controller's LSASS to accept");
    eprintln!("  a master password ('mimikatz') alongside normal credentials.");
    eprintln!("  Requires:");
    eprintln!("    - Running on a Domain Controller");
    eprintln!("    - SeDebugPrivilege");
    eprintln!("    - Patching kdcsvc.dll / msv1_0.dll in LSASS memory");
    eprintln!("    - Modifying the RC4 HMAC validation routine to accept a second key");
    Status::Unsuccessful
}

// ===========================================================================
// misc::compress -- File compression using NT6 APIs
// ===========================================================================

fn cmd_compress(args: &[String]) -> Status {
    let in_path = display::find_named_arg(args, "in");
    let out_path = display::find_named_arg(args, "out");

    if in_path.is_none() || out_path.is_none() {
        eprintln!("ERROR: /in:input_file and /out:output_file required");
        eprintln!("  Usage: misc::compress /in:payload.exe /out:payload.compressed");
        return Status::Unsuccessful;
    }

    let in_file = in_path.unwrap();
    let out_file = out_path.unwrap();

    #[cfg(windows)]
    {
        println!("\nCompressing: {} -> {}", in_file, out_file);

        // Read input file
        let input_data = match std::fs::read(in_file) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("ERROR: Failed to read '{}': {}", in_file, e);
                return Status::Unsuccessful;
            }
        };

        println!("  Input size : {} bytes", input_data.len());

        // A full implementation would:
        // 1. LoadLibraryW("ntdll.dll")
        // 2. GetProcAddress(h, "RtlGetCompressionWorkSpaceSize")
        // 3. GetProcAddress(h, "RtlCompressBuffer")
        // 4. Call RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD, ...)
        // 5. Allocate workspace
        // 6. Call RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1, input, input_len, output, output_len, 4096, &final_size, workspace)
        // 7. Write output to file

        eprintln!("NOTE: Compression requires RtlCompressBuffer from ntdll.dll.");
        eprintln!("  Compression format: LZNT1 (0x0002)");
        eprintln!("  Implementation pending -- requires ntdll dynamic loading.");

        return Status::Success;
    }

    #[cfg(not(windows))]
    {
        let _ = (in_file, out_file);
        eprintln!("ERROR: misc::compress requires Windows (ntdll.dll RtlCompressBuffer)");
        Status::Unsuccessful
    }
}
