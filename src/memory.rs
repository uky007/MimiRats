//! Memory reading abstraction for LSASS process and minidump files.
//!
//! Provides `ProcessMemory` (Windows-only, live process reading via Win32 API)
//! and `MinidumpMemory` (cross-platform, offline `.dmp` file parsing).
#[allow(dead_code)]
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

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

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    let mut c = Cursor::new(&data[offset..offset + 8]);
    c.read_u64::<LittleEndian>().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Windows live process memory reader
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub mod process {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::*;
    use windows::Win32::System::Threading::*;

    /// Handle to a remote process opened for memory reading.
    pub struct ProcessMemory {
        handle: HANDLE,
    }

    impl ProcessMemory {
        /// Open a process by PID with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`.
        pub fn open(pid: u32) -> Result<Self, String> {
            unsafe {
                let handle = OpenProcess(
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    false,
                    pid,
                )
                .map_err(|e| format!("OpenProcess({}): {}", pid, e))?;

                if handle.is_invalid() {
                    return Err(format!("OpenProcess({}) returned invalid handle", pid));
                }

                Ok(ProcessMemory { handle })
            }
        }

        /// Read `size` bytes from the remote process at virtual address `addr`.
        pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, String> {
            let mut buf = vec![0u8; size];
            let mut bytes_read: usize = 0;
            unsafe {
                ReadProcessMemory(
                    self.handle,
                    addr as *const std::ffi::c_void,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    size,
                    Some(&mut bytes_read),
                )
                .map_err(|e| format!("ReadProcessMemory(0x{:X}, {}): {}", addr, size, e))?;
            }
            buf.truncate(bytes_read);
            Ok(buf)
        }

        /// Search for a byte pattern in the remote process address space between
        /// `start` and `end`.
        ///
        /// Uses `VirtualQueryEx` to enumerate committed, readable memory regions
        /// and scans each region for the pattern.
        pub fn search(
            &self,
            pattern: &[u8],
            start: u64,
            end: u64,
        ) -> Result<Vec<u64>, String> {
            if pattern.is_empty() {
                return Ok(Vec::new());
            }

            let mut matches = Vec::new();
            let mut addr = start;

            while addr < end {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let ret = unsafe {
                    VirtualQueryEx(
                        self.handle,
                        Some(addr as *const std::ffi::c_void),
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };

                if ret == 0 {
                    break;
                }

                let region_base = mbi.BaseAddress as u64;
                let region_size = mbi.RegionSize as u64;
                let region_end = region_base + region_size;

                // Only scan committed, readable regions.
                if mbi.State == MEM_COMMIT
                    && (mbi.Protect == PAGE_READONLY
                        || mbi.Protect == PAGE_READWRITE
                        || mbi.Protect == PAGE_EXECUTE_READ
                        || mbi.Protect == PAGE_EXECUTE_READWRITE
                        || mbi.Protect == PAGE_WRITECOPY
                        || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
                {
                    // Read the region and scan for the pattern.
                    if let Ok(data) = self.read(region_base, region_size as usize) {
                        let mut pos = 0;
                        while pos + pattern.len() <= data.len() {
                            if &data[pos..pos + pattern.len()] == pattern {
                                let found_addr = region_base + pos as u64;
                                if found_addr >= start && found_addr < end {
                                    matches.push(found_addr);
                                }
                            }
                            pos += 1;
                        }
                    }
                }

                // Advance to the next region.
                addr = region_end;
                if region_end <= region_base {
                    break; // overflow guard
                }
            }

            Ok(matches)
        }
    }

    impl Drop for ProcessMemory {
        fn drop(&mut self) {
            if !self.handle.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub for ProcessMemory
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
#[allow(dead_code)]
pub mod process {
    /// Stub process memory reader for non-Windows platforms.
    ///
    /// All methods return errors; live process memory reading requires Windows.
    pub struct ProcessMemory {
        _private: (),
    }

    impl ProcessMemory {
        pub fn open(_pid: u32) -> Result<Self, String> {
            Err("ProcessMemory::open is only available on Windows".into())
        }

        pub fn read(&self, _addr: u64, _size: usize) -> Result<Vec<u8>, String> {
            Err("ProcessMemory::read is only available on Windows".into())
        }

        pub fn search(
            &self,
            _pattern: &[u8],
            _start: u64,
            _end: u64,
        ) -> Result<Vec<u64>, String> {
            Err("ProcessMemory::search is only available on Windows".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Minidump file parser (cross-platform)
// ---------------------------------------------------------------------------

/// MDMP signature (`MDMP` in little-endian).
const MDMP_SIGNATURE: u32 = 0x504D_444D;

/// Minidump stream type constants.
const STREAM_TYPE_MODULE_LIST: u32 = 4;
const STREAM_TYPE_MEMORY64_LIST: u32 = 9;

/// Information about a loaded module in the minidump.
pub struct MinidumpModule {
    pub name: String,
    pub base_address: u64,
    pub size: u32,
}

/// A contiguous memory range captured in the minidump.
struct MemoryRange {
    start_address: u64,
    data_offset: u64,
    data_size: u64,
}

/// Cross-platform minidump memory reader.
///
/// Parses a Windows minidump (`.dmp`) file and provides methods to read
/// virtual memory, enumerate modules, and search for byte patterns.
pub struct MinidumpMemory {
    data: Vec<u8>,
    modules: Vec<MinidumpModule>,
    memory_ranges: Vec<MemoryRange>,
}

impl MinidumpMemory {
    /// Open and parse a minidump file.
    ///
    /// Validates the `MDMP` signature, parses the stream directory, and
    /// extracts `ModuleListStream` and `Memory64ListStream` data.
    pub fn open(path: &str) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read minidump '{}': {}", path, e))?;

        if data.len() < 32 {
            return Err("File too small to be a valid minidump".into());
        }

        // MINIDUMP_HEADER validation
        let signature = read_u32_le(&data, 0x00);
        if signature != MDMP_SIGNATURE {
            return Err(format!(
                "Invalid minidump signature: expected 0x{:08X}, got 0x{:08X}",
                MDMP_SIGNATURE, signature
            ));
        }

        let num_streams = read_u32_le(&data, 0x08) as usize;
        let stream_dir_rva = read_u32_le(&data, 0x0C) as usize;

        let mut modules = Vec::new();
        let mut memory_ranges = Vec::new();

        // Parse stream directory.
        // Each MINIDUMP_DIRECTORY entry is 12 bytes: u32 type, u32 size, u32 rva.
        for i in 0..num_streams {
            let dir_off = stream_dir_rva + i * 12;
            if dir_off + 12 > data.len() {
                break;
            }

            let stream_type = read_u32_le(&data, dir_off);
            let _data_size = read_u32_le(&data, dir_off + 4);
            let data_rva = read_u32_le(&data, dir_off + 8) as usize;

            match stream_type {
                STREAM_TYPE_MODULE_LIST => {
                    modules = Self::parse_module_list(&data, data_rva)?;
                }
                STREAM_TYPE_MEMORY64_LIST => {
                    memory_ranges = Self::parse_memory64_list(&data, data_rva)?;
                }
                _ => {
                    // Other stream types are ignored for now.
                }
            }
        }

        Ok(MinidumpMemory {
            data,
            modules,
            memory_ranges,
        })
    }

    /// Read `size` bytes from virtual address `addr` using the captured memory
    /// ranges in the minidump.
    #[allow(dead_code)]
    pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        if size == 0 {
            return Ok(Vec::new());
        }

        // Find the memory range that contains the requested address.
        for range in &self.memory_ranges {
            let range_end = range.start_address + range.data_size;
            if addr >= range.start_address && addr < range_end {
                let offset_in_range = (addr - range.start_address) as u64;
                let available = (range.data_size - offset_in_range) as usize;
                let read_len = size.min(available);

                let file_offset = (range.data_offset + offset_in_range) as usize;
                if file_offset + read_len > self.data.len() {
                    return Err(format!(
                        "Memory range data at file offset 0x{:X} extends beyond file",
                        file_offset
                    ));
                }

                let result = self.data[file_offset..file_offset + read_len].to_vec();
                if result.len() < size {
                    return Err(format!(
                        "Partial read at 0x{:X}: wanted {} bytes, got {}",
                        addr,
                        size,
                        result.len()
                    ));
                }
                return Ok(result);
            }
        }

        Err(format!(
            "Address 0x{:X} not found in any memory range",
            addr
        ))
    }

    /// Look up a module by name (case-insensitive).
    ///
    /// Matches against both the full path and the bare filename.
    pub fn get_module_info(&self, name: &str) -> Option<&MinidumpModule> {
        let target = name.to_ascii_lowercase();
        self.modules.iter().find(|m| {
            let full = m.name.to_ascii_lowercase();
            if full == target {
                return true;
            }
            // Also match against just the filename component.
            if let Some(fname) = full.rsplit('\\').next() {
                if fname == target {
                    return true;
                }
            }
            false
        })
    }

    /// Search all captured memory ranges for a byte pattern, returning a
    /// vector of virtual addresses where the pattern was found.
    pub fn search(&self, pattern: &[u8]) -> Vec<u64> {
        if pattern.is_empty() {
            return Vec::new();
        }

        let mut matches = Vec::new();

        for range in &self.memory_ranges {
            let file_start = range.data_offset as usize;
            let file_end = file_start + range.data_size as usize;

            if file_end > self.data.len() || file_start >= self.data.len() {
                continue;
            }

            let region = &self.data[file_start..file_end.min(self.data.len())];

            let mut pos = 0;
            while pos + pattern.len() <= region.len() {
                if &region[pos..pos + pattern.len()] == pattern {
                    let virtual_addr = range.start_address + pos as u64;
                    matches.push(virtual_addr);
                }
                pos += 1;
            }
        }

        matches
    }

    // -----------------------------------------------------------------------
    // Internal parsers
    // -----------------------------------------------------------------------

    /// Parse the ModuleListStream.
    ///
    /// Layout:
    /// - +0x00: u32 number_of_modules
    /// - +0x04: array of MINIDUMP_MODULE entries (108 bytes each)
    ///
    /// MINIDUMP_MODULE:
    /// - +0x00: u64 base_address
    /// - +0x08: u32 size_of_image
    /// - +0x2C: u32 module_name_rva
    fn parse_module_list(data: &[u8], rva: usize) -> Result<Vec<MinidumpModule>, String> {
        if rva + 4 > data.len() {
            return Err("ModuleListStream RVA out of bounds".into());
        }

        let count = read_u32_le(data, rva) as usize;
        let mut modules = Vec::with_capacity(count);

        // Each MINIDUMP_MODULE is 108 bytes.
        const MODULE_ENTRY_SIZE: usize = 108;
        let entries_start = rva + 4;

        for i in 0..count {
            let entry_off = entries_start + i * MODULE_ENTRY_SIZE;
            if entry_off + MODULE_ENTRY_SIZE > data.len() {
                break;
            }

            let base_address = read_u64_le(data, entry_off);
            let size = read_u32_le(data, entry_off + 0x08);
            let name_rva = read_u32_le(data, entry_off + 0x2C) as usize;

            let name = Self::read_minidump_string(data, name_rva);

            modules.push(MinidumpModule {
                name,
                base_address,
                size,
            });
        }

        Ok(modules)
    }

    /// Parse the Memory64ListStream.
    ///
    /// Layout:
    /// - +0x00: u64 number_of_memory_ranges
    /// - +0x08: u64 base_rva (file offset where the raw memory data begins)
    /// - +0x10: array of MINIDUMP_MEMORY_DESCRIPTOR64 entries (u64 start, u64 size)
    fn parse_memory64_list(data: &[u8], rva: usize) -> Result<Vec<MemoryRange>, String> {
        if rva + 16 > data.len() {
            return Err("Memory64ListStream RVA out of bounds".into());
        }

        let count = read_u64_le(data, rva) as usize;
        let base_rva = read_u64_le(data, rva + 8);

        let mut ranges = Vec::with_capacity(count);
        let entries_start = rva + 16;
        let mut current_data_offset = base_rva;

        for i in 0..count {
            let entry_off = entries_start + i * 16;
            if entry_off + 16 > data.len() {
                break;
            }

            let start_address = read_u64_le(data, entry_off);
            let data_size = read_u64_le(data, entry_off + 8);

            ranges.push(MemoryRange {
                start_address,
                data_offset: current_data_offset,
                data_size,
            });

            current_data_offset += data_size;
        }

        Ok(ranges)
    }

    /// Read a MINIDUMP_STRING (length-prefixed UTF-16LE) at the given RVA.
    ///
    /// Layout:
    /// - +0x00: u32 length (in bytes, not including null terminator)
    /// - +0x04: UTF-16LE character data
    fn read_minidump_string(data: &[u8], rva: usize) -> String {
        if rva + 4 > data.len() {
            return String::new();
        }

        let byte_len = read_u32_le(data, rva) as usize;
        let str_start = rva + 4;

        if str_start + byte_len > data.len() {
            return String::new();
        }

        let u16_count = byte_len / 2;
        let mut chars = Vec::with_capacity(u16_count);
        for i in 0..u16_count {
            chars.push(read_u16_le(data, str_start + i * 2));
        }

        String::from_utf16_lossy(&chars)
    }
}
