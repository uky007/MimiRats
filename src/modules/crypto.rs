//! Crypto module — cryptographic provider and certificate enumeration.
//!
//! Provides hash computation (`crypto::hash`), certificate store browsing,
//! and cryptographic provider enumeration via CryptoAPI and CNG.

use crate::module::{Command, Module, Status};
use crate::display;
use crate::crypto;

pub static MODULE: Module = Module {
    short_name: "crypto",
    full_name: "Crypto module",
    description: "",
    commands: &COMMANDS,
    init: Some(init),
    clean: Some(clean),
};

fn init() -> Status {
    // Original loads rsaenh.dll and dssenh.dll for CPExportKey
    Status::Success
}

fn clean() -> Status {
    // Original frees DLL handles
    Status::Success
}

static COMMANDS: [Command; 14] = [
    Command { name: "providers", description: "List cryptographic providers", handler: cmd_providers },
    Command { name: "stores", description: "List cryptographic stores", handler: cmd_stores },
    Command { name: "certificates", description: "List (or export) certificates", handler: cmd_certificates },
    Command { name: "keys", description: "List (or export) keys containers", handler: cmd_keys },
    Command { name: "sc", description: "List smartcard readers", handler: cmd_sc },
    Command { name: "hash", description: "Hash a password with optional username", handler: cmd_hash },
    Command { name: "system", description: "Describe a Windows System Certificate", handler: cmd_system },
    Command { name: "scauth", description: "Create a authentication certificate", handler: not_impl },
    Command { name: "certtohw", description: "Try to export a software CA to crypto hardware", handler: not_impl },
    Command { name: "capi", description: "[experimental] Patch CryptoAPI layer for easy export", handler: not_impl },
    Command { name: "cng", description: "[experimental] Patch CNG service for easy export", handler: not_impl },
    Command { name: "extract", description: "[experimental] Extract keys from CAPI RSA/AES provider", handler: not_impl },
    Command { name: "kutil", description: "Key utility", handler: not_impl },
    Command { name: "tpminfo", description: "Display TPM info", handler: not_impl },
];

// ---------------------------------------------------------------------------
// hash command — fully cross-platform
// ---------------------------------------------------------------------------

fn cmd_hash(args: &[String]) -> Status {
    let password = match display::find_named_arg(args, "password") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("ERROR: /password:xxx argument is required");
            eprintln!("Usage: crypto::hash /password:xxx [/user:xxx] [/domain:xxx] [/count:N]");
            return Status::Unsuccessful;
        }
    };

    let user = display::find_named_arg(args, "user").map(|s| s.to_string());
    let domain = display::find_named_arg(args, "domain").map(|s| s.to_string());
    let count: u32 = display::find_named_arg(args, "count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10240);

    println!();

    // NTLM hash
    let nt = crypto::nt_hash(&password);
    println!("NTLM  : {}", hex::encode(&nt));

    // LM hash — only valid for passwords <= 14 ASCII characters
    if password.len() <= 14 && password.is_ascii() {
        let lm = crypto::lm_hash(&password);
        println!("LM    : {}", hex::encode(&lm));
    } else {
        println!("LM    : (password too long or non-ASCII for LM hash)");
    }

    // Domain Cached Credentials (require username)
    if let Some(ref username) = user {
        let display_domain = domain.as_deref().unwrap_or("");
        let display_account = if display_domain.is_empty() {
            username.clone()
        } else {
            format!("{}\\{}", display_domain, username)
        };

        let dcc1 = crypto::dcc_v1(&nt, username);
        println!("DCC1  : {} ({})", hex::encode(&dcc1), display_account);

        let dcc2 = crypto::dcc_v2(&nt, username, count);
        println!(
            "DCC2  : {} ({}, {})",
            hex::encode(&dcc2),
            display_account,
            count
        );
    } else {
        println!("DCC1  : (requires /user:xxx)");
        println!("DCC2  : (requires /user:xxx)");
    }

    // Generic hashes
    let md5 = crypto::md5_hash(password.as_bytes());
    println!("MD5   : {}", hex::encode(&md5));

    let sha1 = crypto::sha1_hash(password.as_bytes());
    println!("SHA1  : {}", hex::encode(&sha1));

    let sha256 = crypto::sha256_hash(password.as_bytes());
    println!("SHA256: {}", hex::encode(&sha256));

    Status::Success
}

// ---------------------------------------------------------------------------
// providers command — Windows only (CryptEnumProviders)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_providers(_args: &[String]) -> Status {
    use windows::Win32::Security::Cryptography::*;
    use windows::Win32::Foundation::*;
    use windows::core::PWSTR;

    println!("\nCryptoAPI providers:");

    let mut index: u32 = 0;
    loop {
        let mut prov_type: u32 = 0;
        let mut name_len: u32 = 0;

        // First call: get buffer size
        let ok = unsafe {
            CryptEnumProvidersW(
                index,
                None,
                0,
                &mut prov_type,
                PWSTR::null(),
                &mut name_len,
            )
        };

        if ok.is_err() {
            let err = unsafe { GetLastError() };
            if err == ERROR_NO_MORE_ITEMS {
                break;
            }
            // Some other error — stop enumerating
            break;
        }

        // Second call: get name
        let mut name_buf = vec![0u16; (name_len / 2 + 1) as usize];
        let ok = unsafe {
            CryptEnumProvidersW(
                index,
                None,
                0,
                &mut prov_type,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
            )
        };

        if ok.is_ok() {
            let name = String::from_utf16_lossy(
                &name_buf[..name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len())],
            );
            println!(" {:2} - {}", prov_type, name);
        }

        index += 1;
    }

    if index == 0 {
        println!("  (no providers found)");
    }

    Status::Success
}

#[cfg(not(windows))]
fn cmd_providers(_args: &[String]) -> Status {
    eprintln!("ERROR: crypto::providers requires Windows (CryptEnumProviders API)");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// stores command — Windows only (CertEnumSystemStore)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_stores(args: &[String]) -> Status {
    use windows::Win32::Security::Cryptography::*;
    use windows::Win32::Foundation::BOOL;

    let system_store = display::find_named_arg(args, "systemstore").unwrap_or("user");

    let flags = match system_store.to_ascii_lowercase().as_str() {
        "machine" | "localmachine" => {
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
        }
        _ => CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
    };

    println!(
        "\nSystem store: {} (flags: 0x{:08x})",
        system_store, flags
    );

    // CertEnumSystemStore uses a callback. We'll collect results via a boxed closure.
    unsafe extern "system" fn enum_callback(
        _pv_system_store: *const core::ffi::c_void,
        _dw_flags: CERT_SYSTEM_STORE_FLAGS,
        _p_store_info: *const CERT_SYSTEM_STORE_INFO,
        _pv_reserved: *const core::ffi::c_void,
        _pv_arg: *mut core::ffi::c_void,
    ) -> BOOL {
        // The first parameter is a PCWSTR to the store name
        let name_ptr = _pv_system_store as *const u16;
        if !name_ptr.is_null() {
            let mut len = 0;
            while *name_ptr.add(len) != 0 {
                len += 1;
            }
            let name_slice = std::slice::from_raw_parts(name_ptr, len);
            let name = String::from_utf16_lossy(name_slice);
            println!("  {}", name);
        }
        BOOL(1) // continue enumeration
    }

    let result = unsafe {
        CertEnumSystemStore(
            flags,
            None,
            None,
            Some(enum_callback),
        )
    };

    if !result.as_bool() {
        eprintln!("ERROR: CertEnumSystemStore failed");
        return Status::Unsuccessful;
    }

    Status::Success
}

#[cfg(not(windows))]
fn cmd_stores(_args: &[String]) -> Status {
    eprintln!("ERROR: crypto::stores requires Windows (CertEnumSystemStore API)");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// certificates command — Windows only
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_certificates(args: &[String]) -> Status {
    use windows::Win32::Security::Cryptography::*;

    let store_name = display::find_named_arg(args, "store").unwrap_or("My");
    let system_store = display::find_named_arg(args, "systemstore").unwrap_or("user");

    let flags = match system_store.to_ascii_lowercase().as_str() {
        "machine" | "localmachine" => {
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
        }
        _ => CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
    };

    let store_wide: Vec<u16> = store_name.encode_utf16().chain(std::iter::once(0)).collect();

    let h_store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            HCRYPTPROV_LEGACY(0),
            CERT_OPEN_STORE_FLAGS(flags),
            Some(store_wide.as_ptr() as *const core::ffi::c_void),
        )
    };

    let h_store = match h_store {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: CertOpenStore(\"{}\"): {}", store_name, e);
            return Status::Unsuccessful;
        }
    };

    println!(
        "\nCertificates in store '{}' ({}):",
        store_name, system_store
    );
    println!();

    let mut count = 0u32;
    let mut p_cert: *const CERT_CONTEXT = std::ptr::null();

    loop {
        p_cert = unsafe { CertEnumCertificatesInStore(h_store, Some(p_cert)) };
        if p_cert.is_null() {
            break;
        }

        count += 1;
        let cert = unsafe { &*p_cert };

        // Get subject name
        let subject = cert_name_to_string(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
        let issuer = cert_name_to_string(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);

        println!(" #{}", count);
        println!("   Subject: {}", subject);
        println!("   Issuer : {}", issuer);
        println!();
    }

    if count == 0 {
        println!("  (no certificates found)");
    } else {
        println!("{} certificate(s) found", count);
    }

    unsafe {
        let _ = CertCloseStore(h_store, 0);
    }

    Status::Success
}

#[cfg(windows)]
fn cert_name_to_string(
    cert: &windows::Win32::Security::Cryptography::CERT_CONTEXT,
    name_type: u32,
    flags: u32,
) -> String {
    use windows::Win32::Security::Cryptography::*;

    let len = unsafe {
        CertGetNameStringW(cert, name_type, flags, None, None)
    };
    if len <= 1 {
        return String::from("(unknown)");
    }

    let mut buf = vec![0u16; len as usize];
    unsafe {
        CertGetNameStringW(cert, name_type, flags, None, Some(&mut buf));
    }

    // Remove trailing null
    if let Some(pos) = buf.iter().position(|&c| c == 0) {
        buf.truncate(pos);
    }
    String::from_utf16_lossy(&buf)
}

#[cfg(not(windows))]
fn cmd_certificates(_args: &[String]) -> Status {
    eprintln!("ERROR: crypto::certificates requires Windows (CertOpenStore API)");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// keys command — stub
// ---------------------------------------------------------------------------

fn cmd_keys(_args: &[String]) -> Status {
    println!("crypto::keys - List cryptographic key containers");
    println!("  Not yet implemented. Requires CryptGetProvParam with PP_ENUMCONTAINERS.");
    #[cfg(not(windows))]
    {
        eprintln!("ERROR: crypto::keys requires Windows");
    }
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// sc command — stub
// ---------------------------------------------------------------------------

fn cmd_sc(_args: &[String]) -> Status {
    println!("crypto::sc - List smartcard readers");
    println!("  Not yet implemented. Requires SCardEstablishContext / SCardListReaders.");
    #[cfg(not(windows))]
    {
        eprintln!("ERROR: crypto::sc requires Windows");
    }
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// system command — stub
// ---------------------------------------------------------------------------

fn cmd_system(_args: &[String]) -> Status {
    println!("crypto::system - Describe a Windows System Certificate");
    println!("  Not yet implemented. Requires certificate file parsing or registry access.");
    #[cfg(not(windows))]
    {
        eprintln!("ERROR: crypto::system requires Windows");
    }
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// not_impl — standard stub for unimplemented commands
// ---------------------------------------------------------------------------

fn not_impl(_args: &[String]) -> Status {
    eprintln!("ERROR: This crypto subcommand is not yet implemented");
    Status::Unsuccessful
}
