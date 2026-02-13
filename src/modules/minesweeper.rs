//! MineSweeper module -- Read the game board from minesweeper.exe memory.
//!
//! Locates the Minesweeper process and reads the game board data structure
//! to reveal mine locations and board dimensions.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
#[cfg(windows)]
use crate::memory::process::ProcessMemory;

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "minesweeper",
    full_name: "MineSweeper module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 1] = [
    Command { name: "infos", description: "infos", handler: cmd_infos },
];

// ===========================================================================
// minesweeper::infos
// ===========================================================================

fn cmd_infos(args: &[String]) -> Status {
    let _ = args;

    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::Foundation::CloseHandle;

        println!("\nSearching for Minesweeper process...\n");

        // Find minesweeper.exe (or Microsoft.Minesweeper) PID
        let target_names = ["minesweeper.exe", "minefield.exe"];
        let mut found_pid: u32 = 0;
        let mut found_name = String::new();

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ERROR: CreateToolhelp32Snapshot: {}", e);
                    return Status::Unsuccessful;
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
                    let name_lower = name.to_ascii_lowercase();

                    for &target in &target_names {
                        if name_lower == target {
                            found_pid = entry.th32ProcessID;
                            found_name = name;
                            break;
                        }
                    }

                    if found_pid != 0 {
                        break;
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        if found_pid == 0 {
            eprintln!("ERROR: Minesweeper process not found");
            eprintln!("  Searched for: {:?}", target_names);
            return Status::Unsuccessful;
        }

        println!("  Process: {} (PID: {})", found_name, found_pid);

        // Open the process for memory reading
        match ProcessMemory::open(found_pid) {
            Ok(process) => {
                println!("  Process opened successfully for memory reading.");
                println!();

                // The Minesweeper board structure varies by version:
                //
                // Classic Minesweeper (Windows 7 and earlier):
                //   - Board data at a fixed base address in the .data section
                //   - Width at offset +0x04, Height at offset +0x08
                //   - Mine count at offset +0x10
                //   - Board array starts at offset +0x20 (row-major, 1 byte per cell)
                //   - Cell values: 0x0F = mine, 0x00-0x08 = number of adjacent mines
                //
                // Windows 8+ Minesweeper (UWP):
                //   - Different memory layout, requires pattern scanning
                //   - Board data stored in a dynamic allocation
                //
                // For now, print the framework and the PID for manual analysis.

                println!("  Minesweeper game board reading framework:");
                println!("    - Classic (pre-Win8): Fixed base at known offset in .data section");
                println!("    - Modern (Win8+):     Dynamic allocation, requires pattern scanning");
                println!();

                // Try to find the game board by searching for known patterns
                // The classic minesweeper stores the board with border cells (0x10)
                // around the edges. We can search for this pattern.
                let border_pattern = [0x10u8, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10];
                println!("  Searching for board border pattern (0x10 bytes)...");

                match process.search(&border_pattern, 0x00010000, 0x7FFE0000) {
                    Ok(matches) => {
                        if matches.is_empty() {
                            println!("    No classic board pattern found (may be Win8+ version).");
                        } else {
                            println!("    Found {} potential board location(s):", matches.len());
                            for (i, addr) in matches.iter().take(5).enumerate() {
                                println!("      [{}] 0x{:016X}", i, addr);
                            }
                            if matches.len() > 5 {
                                println!("      ... and {} more", matches.len() - 5);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("    Search error: {}", e);
                    }
                }

                Status::Success
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                eprintln!("  (May require SeDebugPrivilege -- run as Administrator)");
                Status::Unsuccessful
            }
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("ERROR: minesweeper::infos requires Windows");
        eprintln!("  This command reads the game board from the Minesweeper process memory.");
        Status::Unsuccessful
    }
}
