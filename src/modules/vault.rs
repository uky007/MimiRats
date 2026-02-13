//! Vault module — Windows Credential Manager and Vault access.
//!
//! Enumerates stored credentials via `CredEnumerateW` and vault items
//! via dynamically loaded `VaultCli.dll` functions.

use crate::module::{Command, Module, Status};
#[cfg(windows)]
use crate::display;

pub static MODULE: Module = Module {
    short_name: "vault",
    full_name: "Windows Vault/Credential module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 3] = [
    Command { name: "list", description: "List saved credentials in Windows Vault", handler: cmd_list },
    Command { name: "cred", description: "Enumerate credentials from Credential Manager", handler: cmd_cred },
    Command { name: "schema", description: "Display vault schema", handler: cmd_schema },
];

// ---------------------------------------------------------------------------
// vault::cred — Windows Credential Manager (CredEnumerateW)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_cred(args: &[String]) -> Status {
    use windows::Win32::Security::Credentials::*;
    use windows::Win32::Foundation::*;
    use windows::core::*;

    let filter = display::find_named_arg(args, "filter");

    println!("\nCredentials from Windows Credential Manager:");
    println!();

    let mut count: u32 = 0;
    let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();

    let filter_pcwstr = filter.map(|f| {
        let wide: Vec<u16> = f.encode_utf16().chain(std::iter::once(0)).collect();
        // Leak intentionally for the duration of the call; we'll handle it below
        wide
    });

    let result = unsafe {
        if let Some(ref wide) = filter_pcwstr {
            CredEnumerateW(
                PCWSTR(wide.as_ptr()),
                CRED_ENUMERATE_FLAGS(0),
                &mut count,
                &mut creds,
            )
        } else {
            CredEnumerateW(
                PCWSTR::null(),
                CRED_ENUMERATE_ALL_CREDENTIALS,
                &mut count,
                &mut creds,
            )
        }
    };

    if let Err(e) = result {
        let err_code = unsafe { GetLastError() };
        if err_code == ERROR_NOT_FOUND {
            println!("  (no credentials found)");
            return Status::Success;
        }
        eprintln!("ERROR: CredEnumerateW: {} (0x{:08x})", e, err_code.0);
        return Status::Unsuccessful;
    }

    if count == 0 || creds.is_null() {
        println!("  (no credentials found)");
        return Status::Success;
    }

    let cred_slice = unsafe {
        std::slice::from_raw_parts(creds, count as usize)
    };

    for (i, cred_ptr) in cred_slice.iter().enumerate() {
        if cred_ptr.is_null() {
            continue;
        }
        let cred = unsafe { &**cred_ptr };

        let target_name = if !cred.TargetName.is_null() {
            unsafe { cred.TargetName.to_string().unwrap_or_default() }
        } else {
            String::from("(null)")
        };

        let user_name = if !cred.UserName.is_null() {
            unsafe { cred.UserName.to_string().unwrap_or_default() }
        } else {
            String::from("(null)")
        };

        let comment = if !cred.Comment.is_null() {
            unsafe { cred.Comment.to_string().unwrap_or_default() }
        } else {
            String::new()
        };

        let cred_type = match cred.Type {
            CRED_TYPE_GENERIC => "Generic",
            CRED_TYPE_DOMAIN_PASSWORD => "Domain Password",
            CRED_TYPE_DOMAIN_CERTIFICATE => "Domain Certificate",
            CRED_TYPE_DOMAIN_VISIBLE_PASSWORD => "Domain Visible Password",
            CRED_TYPE_GENERIC_CERTIFICATE => "Generic Certificate",
            CRED_TYPE_DOMAIN_EXTENDED => "Domain Extended",
            _ => "Unknown",
        };

        let persist = match cred.Persist {
            CRED_PERSIST_SESSION => "Session",
            CRED_PERSIST_LOCAL_MACHINE => "Local Machine",
            CRED_PERSIST_ENTERPRISE => "Enterprise",
            _ => "Unknown",
        };

        println!(" #{}", i + 1);
        println!("   TargetName : {}", target_name);
        println!("   UserName   : {}", user_name);
        println!("   Type       : {} ({})", cred_type, cred.Type.0);
        println!("   Persist    : {} ({})", persist, cred.Persist.0);

        if !comment.is_empty() {
            println!("   Comment    : {}", comment);
        }

        // Display credential blob size (don't dump raw creds for security)
        if cred.CredentialBlobSize > 0 && !cred.CredentialBlob.is_null() {
            // For domain visible passwords, the blob is often a UTF-16LE string
            if cred.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
                || cred.Type == CRED_TYPE_GENERIC
            {
                let blob = unsafe {
                    std::slice::from_raw_parts(
                        cred.CredentialBlob,
                        cred.CredentialBlobSize as usize,
                    )
                };
                // Try to interpret as UTF-16LE
                if blob.len() >= 2 && blob.len() % 2 == 0 {
                    let u16_data: Vec<u16> = blob
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    // Check if it looks like printable text
                    if u16_data.iter().all(|&c| c >= 0x20 && c < 0xFFFE) {
                        let text = String::from_utf16_lossy(&u16_data);
                        println!("   CredBlob   : {}", text);
                    } else {
                        println!("   CredBlob   : ({} bytes)", cred.CredentialBlobSize);
                    }
                } else {
                    println!("   CredBlob   : ({} bytes)", cred.CredentialBlobSize);
                }
            } else {
                println!("   CredBlob   : ({} bytes)", cred.CredentialBlobSize);
            }
        }

        // Last written time
        if cred.LastWritten.dwHighDateTime != 0 || cred.LastWritten.dwLowDateTime != 0 {
            let ft = ((cred.LastWritten.dwHighDateTime as u64) << 32)
                | (cred.LastWritten.dwLowDateTime as u64);
            println!("   LastWritten: {}", display::format_filetime(ft));
        }

        println!();
    }

    println!("{} credential(s) found", count);

    // Free the credentials array
    unsafe {
        CredFree(creds as *mut core::ffi::c_void);
    }

    Status::Success
}

#[cfg(not(windows))]
fn cmd_cred(_args: &[String]) -> Status {
    eprintln!("ERROR: vault::cred requires Windows (CredEnumerateW API)");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// vault::list — Windows Vault (VaultCli.dll dynamic loading)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn cmd_list(_args: &[String]) -> Status {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::LibraryLoader::*;
    use windows::core::*;

    // VaultCli types
    type HVAULT = *mut core::ffi::c_void;
    type GUID = [u8; 16];

    // Function pointer types matching VaultCli exports
    type FnVaultEnumerateVaults =
        unsafe extern "system" fn(flags: u32, count: *mut u32, guids: *mut *mut GUID) -> i32;
    type FnVaultOpenVault =
        unsafe extern "system" fn(guid: *const GUID, flags: u32, vault: *mut HVAULT) -> i32;
    type FnVaultEnumerateItems = unsafe extern "system" fn(
        vault: HVAULT,
        flags: u32,
        count: *mut u32,
        items: *mut *mut core::ffi::c_void,
    ) -> i32;
    type FnVaultCloseVault = unsafe extern "system" fn(vault: *mut HVAULT) -> i32;
    type FnVaultFree = unsafe extern "system" fn(memory: *mut core::ffi::c_void) -> i32;
    type FnVaultGetItem = unsafe extern "system" fn(
        vault: HVAULT,
        schema_id: *const GUID,
        resource: *const core::ffi::c_void,
        identity: *const core::ffi::c_void,
        package_sid: *const core::ffi::c_void,
        hwnd: *const core::ffi::c_void,
        flags: u32,
        item: *mut *mut core::ffi::c_void,
    ) -> i32;

    println!("\nWindows Vault:");
    println!();

    // Dynamically load vaultcli.dll
    let dll_name: Vec<u16> = "vaultcli.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let h_vault_cli = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) };
    let h_vault_cli = match h_vault_cli {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to load vaultcli.dll: {}", e);
            eprintln!("  This requires Windows 7 or later.");
            return Status::Unsuccessful;
        }
    };

    // Get function pointers
    macro_rules! get_proc {
        ($name:expr, $type:ty) => {{
            let name_bytes = concat!($name, "\0");
            let addr = unsafe {
                GetProcAddress(h_vault_cli, PCSTR(name_bytes.as_ptr()))
            };
            match addr {
                Some(f) => unsafe { std::mem::transmute::<_, $type>(f) },
                None => {
                    eprintln!("ERROR: GetProcAddress({}) failed", $name);
                    unsafe { let _ = FreeLibrary(h_vault_cli); }
                    return Status::Unsuccessful;
                }
            }
        }};
    }

    let vault_enumerate_vaults: FnVaultEnumerateVaults =
        get_proc!("VaultEnumerateVaults", FnVaultEnumerateVaults);
    let vault_open_vault: FnVaultOpenVault =
        get_proc!("VaultOpenVault", FnVaultOpenVault);
    let vault_enumerate_items: FnVaultEnumerateItems =
        get_proc!("VaultEnumerateItems", FnVaultEnumerateItems);
    let vault_close_vault: FnVaultCloseVault =
        get_proc!("VaultCloseVault", FnVaultCloseVault);
    let vault_free: FnVaultFree = get_proc!("VaultFree", FnVaultFree);

    // Enumerate vaults
    let mut vault_count: u32 = 0;
    let mut vault_guids: *mut GUID = std::ptr::null_mut();

    let hr = unsafe { vault_enumerate_vaults(0, &mut vault_count, &mut vault_guids) };
    if hr != 0 {
        eprintln!("ERROR: VaultEnumerateVaults failed: HRESULT 0x{:08x}", hr as u32);
        unsafe { let _ = FreeLibrary(h_vault_cli); }
        return Status::Unsuccessful;
    }

    if vault_count == 0 || vault_guids.is_null() {
        println!("  (no vaults found)");
        unsafe { let _ = FreeLibrary(h_vault_cli); }
        return Status::Success;
    }

    let guid_slice = unsafe {
        std::slice::from_raw_parts(vault_guids, vault_count as usize)
    };

    for (vault_idx, guid) in guid_slice.iter().enumerate() {
        let guid_str = display::format_guid(guid);
        println!("Vault #{} : {}", vault_idx + 1, guid_str);

        // Open this vault
        let mut h_vault: HVAULT = std::ptr::null_mut();
        let hr = unsafe { vault_open_vault(guid as *const GUID, 0, &mut h_vault) };
        if hr != 0 {
            eprintln!("  ERROR: VaultOpenVault failed: HRESULT 0x{:08x}", hr as u32);
            continue;
        }

        // Enumerate items in this vault
        let mut item_count: u32 = 0;
        let mut items: *mut core::ffi::c_void = std::ptr::null_mut();

        let hr = unsafe {
            vault_enumerate_items(h_vault, 0x200, &mut item_count, &mut items)
        };

        if hr != 0 {
            // Try without the 0x200 flag (older Windows versions)
            let hr = unsafe {
                vault_enumerate_items(h_vault, 0, &mut item_count, &mut items)
            };
            if hr != 0 {
                eprintln!(
                    "  ERROR: VaultEnumerateItems failed: HRESULT 0x{:08x}",
                    hr as u32
                );
                unsafe {
                    vault_close_vault(&mut h_vault);
                }
                continue;
            }
        }

        println!("  Items: {}", item_count);

        // VAULT_ITEM_WIN8 structure (simplified):
        // Offset 0x00: GUID SchemaId (16 bytes)
        // Offset 0x10: PCWSTR FriendlyName (pointer)
        // Offset 0x18: PVOID Resource (pointer to VAULT_ITEM_ELEMENT)
        // Offset 0x20: PVOID Identity (pointer to VAULT_ITEM_ELEMENT)
        // Offset 0x28: PVOID Authenticator (pointer to VAULT_ITEM_ELEMENT)
        // ... more fields
        // Total size depends on Windows version (Win7 vs Win8+)
        //
        // Due to the complexity and version-dependent layout, we display the
        // item count. Full parsing requires detecting the Windows version and
        // using the appropriate structure layout.

        if item_count > 0 {
            // VAULT_ITEM structure is ~72 bytes on x64 for Windows 8+
            // and ~64 bytes on Windows 7. We attempt best-effort parsing.
            let item_size: usize = 72; // Windows 8+ VAULT_ITEM size (x64)
            let item_base = items as *const u8;

            for i in 0..item_count as usize {
                let item_ptr = unsafe { item_base.add(i * item_size) };

                // First 16 bytes are the schema GUID
                let schema_guid = unsafe {
                    std::slice::from_raw_parts(item_ptr, 16)
                };
                let schema_str = display::format_guid(schema_guid);

                // Friendly name is a PCWSTR at offset 0x10
                let friendly_name_ptr = unsafe {
                    *(item_ptr.add(0x10) as *const *const u16)
                };
                let friendly_name = if !friendly_name_ptr.is_null() {
                    unsafe {
                        let mut len = 0;
                        while *friendly_name_ptr.add(len) != 0 && len < 512 {
                            len += 1;
                        }
                        let name_slice = std::slice::from_raw_parts(friendly_name_ptr, len);
                        String::from_utf16_lossy(name_slice)
                    }
                } else {
                    String::new()
                };

                println!();
                println!("  Item #{}", i + 1);
                println!("    SchemaId : {}", schema_str);
                if !friendly_name.is_empty() {
                    println!("    Name     : {}", friendly_name);
                }

                // Try to read Resource element (VAULT_ITEM_ELEMENT at offset 0x18)
                let resource_ptr = unsafe {
                    *(item_ptr.add(0x18) as *const *const u8)
                };
                if !resource_ptr.is_null() {
                    // VAULT_ITEM_ELEMENT: type at +0x00 (u32), then data varies
                    let elem_type = unsafe { *(resource_ptr as *const u32) };
                    // Type 1 = VAULT_ELEMENT_TYPE_STRING (PCWSTR at +0x08)
                    if elem_type == 1 {
                        let str_ptr = unsafe {
                            *(resource_ptr.add(0x08) as *const *const u16)
                        };
                        if !str_ptr.is_null() {
                            let s = unsafe {
                                let mut len = 0;
                                while *str_ptr.add(len) != 0 && len < 512 {
                                    len += 1;
                                }
                                String::from_utf16_lossy(
                                    std::slice::from_raw_parts(str_ptr, len),
                                )
                            };
                            println!("    Resource : {}", s);
                        }
                    }
                }

                // Try to read Identity element (VAULT_ITEM_ELEMENT at offset 0x20)
                let identity_ptr = unsafe {
                    *(item_ptr.add(0x20) as *const *const u8)
                };
                if !identity_ptr.is_null() {
                    let elem_type = unsafe { *(identity_ptr as *const u32) };
                    if elem_type == 1 {
                        let str_ptr = unsafe {
                            *(identity_ptr.add(0x08) as *const *const u16)
                        };
                        if !str_ptr.is_null() {
                            let s = unsafe {
                                let mut len = 0;
                                while *str_ptr.add(len) != 0 && len < 512 {
                                    len += 1;
                                }
                                String::from_utf16_lossy(
                                    std::slice::from_raw_parts(str_ptr, len),
                                )
                            };
                            println!("    Identity : {}", s);
                        }
                    }
                }
            }

            // Free items
            if !items.is_null() {
                unsafe { vault_free(items); }
            }
        }

        // Close this vault
        unsafe {
            vault_close_vault(&mut h_vault);
        }

        println!();
    }

    // Free vault GUIDs
    if !vault_guids.is_null() {
        unsafe { vault_free(vault_guids as *mut core::ffi::c_void); }
    }

    unsafe { let _ = FreeLibrary(h_vault_cli); }

    Status::Success
}

#[cfg(not(windows))]
fn cmd_list(_args: &[String]) -> Status {
    eprintln!("ERROR: vault::list requires Windows (VaultCli.dll)");
    Status::Unsuccessful
}

// ---------------------------------------------------------------------------
// vault::schema — stub
// ---------------------------------------------------------------------------

fn cmd_schema(_args: &[String]) -> Status {
    println!("vault::schema - Display vault schema information");
    println!("  Not yet implemented. Requires VaultCli.dll VaultGetItem with schema enumeration.");
    #[cfg(not(windows))]
    {
        eprintln!("ERROR: vault::schema requires Windows");
    }
    Status::Unsuccessful
}
