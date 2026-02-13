//! Registry utilities: live Windows API access and offline hive parsing.
//!
//! The `api` submodule (Windows-only) wraps Win32 registry functions.
//! The `HiveFile` struct provides cross-platform offline registry hive parsing.
#[allow(dead_code)]

// ---------------------------------------------------------------------------
// Windows API wrappers
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub mod api {
    use windows::Win32::System::Registry::*;
    use windows::Win32::Foundation::*;
    use windows::core::*;

    /// Open a registry subkey under `hkey` with `KEY_READ` access.
    pub fn reg_open_key(hkey: HKEY, subkey: &str) -> Result<HKEY, String> {
        let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut result_key = HKEY::default();
        unsafe {
            RegOpenKeyExW(
                hkey,
                PCWSTR(wide.as_ptr()),
                0,
                KEY_READ,
                &mut result_key,
            )
            .map_err(|e| format!("RegOpenKeyExW({}): {}", subkey, e))?;
        }
        Ok(result_key)
    }

    /// Query a named value under `hkey`, returning the raw byte data.
    pub fn reg_query_value(hkey: HKEY, name: &str) -> Result<Vec<u8>, String> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // First call: determine required buffer size.
        let mut data_size: u32 = 0;
        let mut data_type: u32 = 0;
        unsafe {
            let status = RegQueryValueExW(
                hkey,
                PCWSTR(wide.as_ptr()),
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_size),
            );
            if status.is_err() {
                return Err(format!("RegQueryValueExW(size, {}): {}", name, status.0));
            }
        }

        if data_size == 0 {
            return Ok(Vec::new());
        }

        // Second call: read data.
        let mut buf = vec![0u8; data_size as usize];
        unsafe {
            let status = RegQueryValueExW(
                hkey,
                PCWSTR(wide.as_ptr()),
                None,
                Some(&mut data_type),
                Some(buf.as_mut_ptr()),
                Some(&mut data_size),
            );
            if status.is_err() {
                return Err(format!("RegQueryValueExW(data, {}): {}", name, status.0));
            }
        }
        buf.truncate(data_size as usize);
        Ok(buf)
    }

    /// Enumerate all subkey names under `hkey`.
    pub fn reg_enum_keys(hkey: HKEY) -> Result<Vec<String>, String> {
        let mut keys = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len: u32 = name_buf.len() as u32;
            unsafe {
                let status = RegEnumKeyExW(
                    hkey,
                    index,
                    PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                );
                if status == Err(WIN32_ERROR(259).into()) {
                    // ERROR_NO_MORE_ITEMS
                    break;
                }
                if status.is_err() {
                    return Err(format!("RegEnumKeyExW({}): {:?}", index, status));
                }
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            keys.push(name);
            index += 1;
        }
        Ok(keys)
    }

    /// Enumerate all values under `hkey`, returning `(name, type, data)` tuples.
    pub fn reg_enum_values(hkey: HKEY) -> Result<Vec<(String, u32, Vec<u8>)>, String> {
        let mut values = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 16384];
            let mut name_len: u32 = name_buf.len() as u32;
            let mut data_type: u32 = 0;
            let mut data_buf = vec![0u8; 65536];
            let mut data_size: u32 = data_buf.len() as u32;

            unsafe {
                let status = RegEnumValueW(
                    hkey,
                    index,
                    PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut data_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_size),
                );
                if status == Err(WIN32_ERROR(259).into()) {
                    break;
                }
                if status.is_err() {
                    return Err(format!("RegEnumValueW({}): {:?}", index, status));
                }
            }

            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            data_buf.truncate(data_size as usize);
            values.push((name, data_type, data_buf));
            index += 1;
        }
        Ok(values)
    }

    /// Close an opened registry key.
    pub fn reg_close_key(hkey: HKEY) {
        unsafe {
            let _ = RegCloseKey(hkey);
        }
    }
}

// ---------------------------------------------------------------------------
// Offline hive parser (cross-platform)
// ---------------------------------------------------------------------------
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

/// Magic bytes at the start of a registry hive file (`regf`).
const REGF_MAGIC: u32 = 0x7265_6766;

/// Base file offset where hive bins begin.
const HBIN_BASE: u32 = 0x1000;

/// NK (key node) cell signature.
const NK_SIGNATURE: u16 = 0x6E6B;

/// VK (value key) cell signature.
const VK_SIGNATURE: u16 = 0x766B;

/// Subkey list signatures.
const LF_SIGNATURE: u16 = 0x666C;
const LH_SIGNATURE: u16 = 0x686C;
const LI_SIGNATURE: u16 = 0x696C;
const RI_SIGNATURE: u16 = 0x6972;

/// NK flag: key name is ASCII (compressed).
const NK_FLAG_COMP_NAME: u16 = 0x0020;

// ---------------------------------------------------------------------------
// Little-endian read helpers
// ---------------------------------------------------------------------------
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    let mut c = Cursor::new(&data[offset..offset + 2]);
    c.read_u16::<LittleEndian>().unwrap_or(0)
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    let mut c = Cursor::new(&data[offset..offset + 4]);
    c.read_u32::<LittleEndian>().unwrap_or(0)
}

#[allow(dead_code)]
fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    let mut c = Cursor::new(&data[offset..offset + 4]);
    c.read_i32::<LittleEndian>().unwrap_or(0)
}

#[allow(dead_code)]
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    let mut c = Cursor::new(&data[offset..offset + 8]);
    c.read_u64::<LittleEndian>().unwrap_or(0)
}

/// Represents an opened (memory-mapped) registry hive file.
pub struct HiveFile {
    data: Vec<u8>,
    root_cell_offset: u32,
}

impl HiveFile {
    /// Open a registry hive file from disk.
    ///
    /// Validates the `regf` magic signature and extracts the root cell offset
    /// from the file header (offset 0x24).
    pub fn open(path: &str) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read hive file '{}': {}", path, e))?;

        if data.len() < HBIN_BASE as usize {
            return Err("File too small to be a valid registry hive".into());
        }

        let magic = read_u32_le(&data, 0);
        if magic != REGF_MAGIC {
            return Err(format!(
                "Invalid hive magic: expected 0x{:08X}, got 0x{:08X}",
                REGF_MAGIC, magic
            ));
        }

        let root_cell_offset = read_u32_le(&data, 0x24);

        Ok(HiveFile {
            data,
            root_cell_offset,
        })
    }

    /// Return the absolute file offset of the root key node cell.
    ///
    /// This is the `root_cell_offset` (relative to hbin base) plus 0x1000.
    pub fn root_key_offset(&self) -> u32 {
        self.root_cell_offset + HBIN_BASE
    }

    /// Navigate a backslash-separated key path starting from `base_offset`.
    ///
    /// Returns the file offset of the target key node cell.
    pub fn open_key(&self, base_offset: u32, path: &str) -> Result<u32, String> {
        let path = path.trim_matches('\\');
        if path.is_empty() {
            return Ok(base_offset);
        }

        let mut current_offset = base_offset;
        for component in path.split('\\') {
            let subkeys = self.enum_keys(current_offset)?;
            let target = component.to_ascii_lowercase();
            let mut found = false;
            for (name, offset) in &subkeys {
                if name.to_ascii_lowercase() == target {
                    current_offset = *offset;
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(format!("Subkey '{}' not found", component));
            }
        }
        Ok(current_offset)
    }

    /// Enumerate the immediate subkeys of the key node at `key_offset`.
    ///
    /// Returns a vector of `(name, file_offset)` pairs.
    pub fn enum_keys(&self, key_offset: u32) -> Result<Vec<(String, u32)>, String> {
        let off = key_offset as usize;
        self.validate_nk(off)?;

        let num_subkeys = read_u32_le(&self.data, off + 0x18);
        if num_subkeys == 0 {
            return Ok(Vec::new());
        }

        let subkey_list_rel = read_u32_le(&self.data, off + 0x20);
        if subkey_list_rel == 0xFFFF_FFFF {
            return Ok(Vec::new());
        }

        let list_offset = (subkey_list_rel + HBIN_BASE) as usize;
        self.read_subkey_list(list_offset)
    }

    /// Find a named value under the key node at `key_offset` and return its
    /// raw data bytes.
    pub fn query_value(&self, key_offset: u32, name: &str) -> Result<Vec<u8>, String> {
        let off = key_offset as usize;
        self.validate_nk(off)?;

        let num_values = read_u32_le(&self.data, off + 0x28);
        if num_values == 0 {
            return Err(format!("Key has no values (looking for '{}')", name));
        }

        let value_list_rel = read_u32_le(&self.data, off + 0x2C);
        if value_list_rel == 0xFFFF_FFFF {
            return Err("Invalid value list offset".into());
        }

        let list_off = (value_list_rel + HBIN_BASE) as usize;
        // The value list cell: skip the cell-size i32, then u32 offsets.
        let list_data_off = list_off + 4; // skip cell size

        let target = name.to_ascii_lowercase();
        for i in 0..num_values as usize {
            let vk_rel = read_u32_le(&self.data, list_data_off + i * 4);
            let vk_off = (vk_rel + HBIN_BASE) as usize;

            let sig = read_u16_le(&self.data, vk_off + 4);
            if sig != VK_SIGNATURE {
                continue;
            }

            let vk_name = self.read_vk_name(vk_off);
            if vk_name.to_ascii_lowercase() == target
                || (target.is_empty() && vk_name.is_empty())
            {
                return self.read_vk_data(vk_off);
            }
        }

        Err(format!("Value '{}' not found", name))
    }

    /// Read the class name data of a key node.
    ///
    /// This is used for SAM syskey extraction where the class name of certain
    /// registry keys contains parts of the boot key.
    pub fn query_class(&self, key_offset: u32) -> Result<Vec<u8>, String> {
        let off = key_offset as usize;
        self.validate_nk(off)?;

        let class_name_offset_rel = read_u32_le(&self.data, off + 0x34);
        let class_name_length = read_u16_le(&self.data, off + 0x4E);

        if class_name_offset_rel == 0xFFFF_FFFF || class_name_length == 0 {
            return Err("Key has no class name".into());
        }

        let class_off = (class_name_offset_rel + HBIN_BASE) as usize;
        // Cell data starts after the cell-size i32.
        let data_start = class_off + 4;
        let len = class_name_length as usize;

        if data_start + len > self.data.len() {
            return Err("Class name data extends beyond file".into());
        }

        Ok(self.data[data_start..data_start + len].to_vec())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Validate that the cell at `off` contains an NK signature.
    fn validate_nk(&self, off: usize) -> Result<(), String> {
        if off + 0x50 > self.data.len() {
            return Err(format!(
                "NK cell offset 0x{:X} out of bounds (file size 0x{:X})",
                off,
                self.data.len()
            ));
        }
        let sig = read_u16_le(&self.data, off + 4);
        if sig != NK_SIGNATURE {
            return Err(format!(
                "Expected NK signature at 0x{:X}, got 0x{:04X}",
                off, sig
            ));
        }
        Ok(())
    }

    /// Read the key name from an NK record.
    fn read_nk_name(&self, off: usize) -> String {
        let flags = read_u16_le(&self.data, off + 0x06);
        let name_len = read_u16_le(&self.data, off + 0x4C) as usize;
        let name_start = off + 0x50;

        if name_start + name_len > self.data.len() {
            return String::new();
        }

        if flags & NK_FLAG_COMP_NAME != 0 {
            // ASCII / compressed name
            String::from_utf8_lossy(&self.data[name_start..name_start + name_len]).into_owned()
        } else {
            // UTF-16LE name
            let u16_count = name_len / 2;
            let mut chars = Vec::with_capacity(u16_count);
            for i in 0..u16_count {
                chars.push(read_u16_le(&self.data, name_start + i * 2));
            }
            String::from_utf16_lossy(&chars)
        }
    }

    /// Read the value name from a VK record.
    fn read_vk_name(&self, vk_off: usize) -> String {
        let name_len = read_u16_le(&self.data, vk_off + 0x06) as usize;
        if name_len == 0 {
            return String::new(); // default value
        }

        let flags = read_u16_le(&self.data, vk_off + 0x14);
        let name_start = vk_off + 0x18;

        if name_start + name_len > self.data.len() {
            return String::new();
        }

        if flags & 0x0001 != 0 {
            // ASCII / compressed name
            String::from_utf8_lossy(&self.data[name_start..name_start + name_len]).into_owned()
        } else {
            // UTF-16LE name
            let u16_count = name_len / 2;
            let mut chars = Vec::with_capacity(u16_count);
            for i in 0..u16_count {
                chars.push(read_u16_le(&self.data, name_start + i * 2));
            }
            String::from_utf16_lossy(&chars)
        }
    }

    /// Read the data for a VK record.
    fn read_vk_data(&self, vk_off: usize) -> Result<Vec<u8>, String> {
        let data_length_raw = read_u32_le(&self.data, vk_off + 0x08);
        let data_offset_raw = read_u32_le(&self.data, vk_off + 0x0C);

        // Bit 31 set means the data is stored inline in the offset field.
        if data_length_raw & 0x8000_0000 != 0 {
            let actual_len = (data_length_raw & 0x7FFF_FFFF) as usize;
            if actual_len > 4 {
                return Err("Inline VK data claims more than 4 bytes".into());
            }
            // The inline data is stored in the bytes of the data_offset field.
            let inline_start = vk_off + 0x0C;
            return Ok(self.data[inline_start..inline_start + actual_len].to_vec());
        }

        let data_len = data_length_raw as usize;
        if data_len == 0 {
            return Ok(Vec::new());
        }

        let data_file_off = (data_offset_raw + HBIN_BASE) as usize;
        // Cell data starts after the cell-size i32.
        let data_start = data_file_off + 4;

        if data_start + data_len > self.data.len() {
            return Err(format!(
                "VK data at 0x{:X} len {} extends beyond file (0x{:X})",
                data_start,
                data_len,
                self.data.len()
            ));
        }

        Ok(self.data[data_start..data_start + data_len].to_vec())
    }

    /// Parse a subkey list cell (lf, lh, li, or ri format).
    fn read_subkey_list(&self, list_offset: usize) -> Result<Vec<(String, u32)>, String> {
        if list_offset + 8 > self.data.len() {
            return Err(format!(
                "Subkey list offset 0x{:X} out of bounds",
                list_offset
            ));
        }

        // Skip cell size (+0x00 i32), signature at +0x04 u16, count at +0x06 u16
        let sig = read_u16_le(&self.data, list_offset + 4);
        let count = read_u16_le(&self.data, list_offset + 6) as usize;

        match sig {
            LF_SIGNATURE | LH_SIGNATURE => {
                // lf/lh: entries are (u32 offset, u32 hash) pairs at +0x08
                let mut result = Vec::with_capacity(count);
                for i in 0..count {
                    let entry_off = list_offset + 8 + i * 8;
                    let nk_rel = read_u32_le(&self.data, entry_off);
                    let nk_file_off = nk_rel + HBIN_BASE;

                    let nk_off = nk_file_off as usize;
                    if nk_off + 0x50 > self.data.len() {
                        continue;
                    }
                    let nk_sig = read_u16_le(&self.data, nk_off + 4);
                    if nk_sig != NK_SIGNATURE {
                        continue;
                    }

                    let name = self.read_nk_name(nk_off);
                    result.push((name, nk_file_off));
                }
                Ok(result)
            }
            LI_SIGNATURE => {
                // li: entries are plain u32 offsets at +0x08
                let mut result = Vec::with_capacity(count);
                for i in 0..count {
                    let entry_off = list_offset + 8 + i * 4;
                    let nk_rel = read_u32_le(&self.data, entry_off);
                    let nk_file_off = nk_rel + HBIN_BASE;

                    let nk_off = nk_file_off as usize;
                    if nk_off + 0x50 > self.data.len() {
                        continue;
                    }
                    let nk_sig = read_u16_le(&self.data, nk_off + 4);
                    if nk_sig != NK_SIGNATURE {
                        continue;
                    }

                    let name = self.read_nk_name(nk_off);
                    result.push((name, nk_file_off));
                }
                Ok(result)
            }
            RI_SIGNATURE => {
                // ri: entries are offsets to other subkey lists (indirect)
                let mut result = Vec::new();
                for i in 0..count {
                    let entry_off = list_offset + 8 + i * 4;
                    let sub_list_rel = read_u32_le(&self.data, entry_off);
                    let sub_list_off = (sub_list_rel + HBIN_BASE) as usize;
                    let mut sub_keys = self.read_subkey_list(sub_list_off)?;
                    result.append(&mut sub_keys);
                }
                Ok(result)
            }
            _ => Err(format!(
                "Unknown subkey list signature 0x{:04X} at offset 0x{:X}",
                sig, list_offset
            )),
        }
    }
}
