//! Token module — Windows access token manipulation.
//!
//! Provides commands for listing, elevating, and impersonating security tokens.
//! Corresponds to mimikatz's `token::` commands.

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "token",
    full_name: "Token manipulation module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 3] = [
    Command {
        name: "whoami",
        description: "Display current identity",
        handler: cmd_whoami,
    },
    Command {
        name: "list",
        description: "List all tokens of the system",
        handler: cmd_list,
    },
    Command {
        name: "revert",
        description: "Revert to process token",
        handler: cmd_revert,
    },
];

#[cfg(windows)]
fn cmd_whoami(_args: &[String]) -> Status {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken};

    unsafe {
        // Process token
        print!(" * Process Token : ");
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            display_token_info(token);
            let _ = CloseHandle(token);
        } else {
            eprintln!("ERROR: OpenProcessToken");
        }

        // Thread token
        print!(" * Thread Token  : ");
        let mut token = HANDLE::default();
        match OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) {
            Ok(()) => {
                display_token_info(token);
                let _ = CloseHandle(token);
            }
            Err(e) => {
                if e.code().0 as u32 == 0x3f0 {
                    // ERROR_NO_TOKEN
                    println!("no token");
                } else {
                    eprintln!("ERROR: OpenThreadToken: {}", e);
                }
            }
        }
    }
    Status::Success
}

#[cfg(windows)]
fn display_token_info(token: windows::Win32::Foundation::HANDLE) {
    use crate::win32::api;

    match api::get_token_user_info(token) {
        Ok((domain, name)) => {
            if domain.is_empty() {
                print!("{}", name);
            } else {
                print!("{}\\{}", domain, name);
            }
        }
        Err(e) => {
            print!("(?): {}", e);
        }
    }

    if let Ok(stats) = api::get_token_statistics(token) {
        let token_type = match stats.TokenType.0 {
            1 => "Primary",
            2 => "Impersonation",
            _ => "Unknown",
        };
        print!("\t({})", token_type);
        if stats.TokenType.0 == 2 {
            let imp_level = match stats.ImpersonationLevel.0 {
                0 => "Anonymous",
                1 => "Identification",
                2 => "Impersonation",
                3 => "Delegation",
                _ => "?",
            };
            print!(" ({})", imp_level);
        }
    }
    println!();
}

#[cfg(not(windows))]
fn cmd_whoami(_args: &[String]) -> Status {
    // Cross-platform fallback: use environment
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        println!(" * Current user : {}", user);
    } else {
        println!(" * Current user : unknown");
    }
    Status::Success
}

fn cmd_list(_args: &[String]) -> Status {
    #[cfg(windows)]
    {
        eprintln!("ERROR: token::list not yet fully implemented");
        // TODO: enumerate all tokens via NtQuerySystemInformation
    }
    #[cfg(not(windows))]
    {
        eprintln!("ERROR: token operations require Windows");
    }
    Status::Unsuccessful
}

#[cfg(windows)]
fn cmd_revert(_args: &[String]) -> Status {
    use windows::Win32::System::Threading::SetThreadToken;
    use windows::Win32::Foundation::HANDLE;

    unsafe {
        match SetThreadToken(None, HANDLE::default()) {
            Ok(()) => {
                println!("Reverted to process token.");
                cmd_whoami(&[]);
            }
            Err(e) => {
                eprintln!("ERROR: SetThreadToken: {}", e);
            }
        }
    }
    Status::Success
}

#[cfg(not(windows))]
fn cmd_revert(_args: &[String]) -> Status {
    eprintln!("ERROR: token operations require Windows");
    Status::Unsuccessful
}
