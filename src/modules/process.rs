//! Process module — process listing and information.
//!
//! Enumerates running processes with PID, parent PID, and executable name.
//! Uses `CreateToolhelp32Snapshot` on Windows.

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "process",
    full_name: "Process module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 5] = [
    Command {
        name: "list",
        description: "List processes",
        handler: cmd_list,
    },
    Command {
        name: "start",
        description: "Start a process",
        handler: cmd_start,
    },
    Command {
        name: "stop",
        description: "Terminate a process",
        handler: cmd_stop,
    },
    Command {
        name: "suspend",
        description: "Suspend a process",
        handler: cmd_suspend,
    },
    Command {
        name: "resume",
        description: "Resume a process",
        handler: cmd_resume,
    },
];

#[cfg(windows)]
fn cmd_list(_args: &[String]) -> Status {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::CloseHandle;

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
            println!("{}\t{}", "PID", "Name");
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())],
                );
                println!("{}\t{}", entry.th32ProcessID, name);
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }
    Status::Success
}

#[cfg(not(windows))]
fn cmd_list(_args: &[String]) -> Status {
    eprintln!("ERROR: process::list requires Windows");
    Status::Unsuccessful
}

#[cfg(windows)]
fn cmd_start(args: &[String]) -> Status {
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows::Win32::Foundation::CloseHandle;

    let cmd_line = match args.last() {
        Some(c) => c,
        None => {
            eprintln!("ERROR: Missing command line argument");
            return Status::Unsuccessful;
        }
    };

    println!("Trying to start \"{}\" : ", cmd_line);
    let mut wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        match CreateProcessW(
            None,
            windows::core::PWSTR(wide.as_mut_ptr()),
            None,
            None,
            false,
            Default::default(),
            None,
            None,
            &si,
            &mut pi,
        ) {
            Ok(()) => {
                println!("OK ! (PID {})", pi.dwProcessId);
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
            }
            Err(e) => {
                eprintln!("ERROR: CreateProcess: {}", e);
            }
        }
    }
    Status::Success
}

#[cfg(not(windows))]
fn cmd_start(args: &[String]) -> Status {
    match args.last() {
        Some(cmd) => {
            eprintln!("ERROR: process::start requires Windows (cmd: {})", cmd);
        }
        None => {
            eprintln!("ERROR: Missing command line argument");
        }
    }
    Status::Unsuccessful
}

#[cfg(windows)]
fn cmd_stop(args: &[String]) -> Status {
    process_generic_operation(args, ProcessOperation::Terminate)
}

#[cfg(windows)]
fn cmd_suspend(args: &[String]) -> Status {
    process_generic_operation(args, ProcessOperation::Suspend)
}

#[cfg(windows)]
fn cmd_resume(args: &[String]) -> Status {
    process_generic_operation(args, ProcessOperation::Resume)
}

#[cfg(windows)]
enum ProcessOperation {
    Terminate,
    Suspend,
    Resume,
}

#[cfg(windows)]
fn process_generic_operation(args: &[String], op: ProcessOperation) -> Status {
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess,
        PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    };
    use windows::Win32::Foundation::CloseHandle;

    // Parse /pid:NNN style argument
    let pid: u32 = match find_named_arg(args, "pid") {
        Some(val) => match val.parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("ERROR: Invalid pid value");
                return Status::Unsuccessful;
            }
        },
        None => {
            eprintln!("ERROR: pid (/pid:123) is missing");
            return Status::Unsuccessful;
        }
    };

    let (access, op_name) = match op {
        ProcessOperation::Terminate => (PROCESS_TERMINATE, "NtTerminateProcess"),
        ProcessOperation::Suspend => (PROCESS_SUSPEND_RESUME, "NtSuspendProcess"),
        ProcessOperation::Resume => (PROCESS_SUSPEND_RESUME, "NtResumeProcess"),
    };

    unsafe {
        let process = match OpenProcess(access, false, pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ERROR: OpenProcess: {}", e);
                return Status::Unsuccessful;
            }
        };

        let result = match op {
            ProcessOperation::Terminate => TerminateProcess(process, 0),
            ProcessOperation::Suspend | ProcessOperation::Resume => {
                // NtSuspendProcess/NtResumeProcess are ntdll functions.
                // Use dynamic loading as they are not in the standard windows crate.
                type NtProcessFn = unsafe extern "system" fn(windows::Win32::Foundation::HANDLE) -> i32;
                let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
                    windows::core::w!("ntdll.dll"),
                );
                if let Ok(h) = ntdll {
                    let func_name = match op {
                        ProcessOperation::Suspend => c"NtSuspendProcess",
                        ProcessOperation::Resume => c"NtResumeProcess",
                        _ => unreachable!(),
                    };
                    if let Some(func) = windows::Win32::System::LibraryLoader::GetProcAddress(h, windows::core::PCSTR(func_name.as_ptr() as *const u8)) {
                        let func: NtProcessFn = std::mem::transmute(func);
                        let ntstatus = func(process);
                        if ntstatus >= 0 {
                            Ok(())
                        } else {
                            Err(windows::core::Error::from_win32())
                        }
                    } else {
                        Err(windows::core::Error::from_win32())
                    }
                } else {
                    Err(windows::core::Error::from_win32())
                }
            }
        };

        let _ = CloseHandle(process);

        match result {
            Ok(()) => {
                println!("{} of {} PID : OK !", op_name, pid);
                Status::Success
            }
            Err(e) => {
                eprintln!("ERROR: {} : {}", op_name, e);
                Status::Unsuccessful
            }
        }
    }
}

#[cfg(not(windows))]
fn cmd_stop(_args: &[String]) -> Status {
    eprintln!("ERROR: process::stop requires Windows");
    Status::Unsuccessful
}

#[cfg(not(windows))]
fn cmd_suspend(_args: &[String]) -> Status {
    eprintln!("ERROR: process::suspend requires Windows");
    Status::Unsuccessful
}

#[cfg(not(windows))]
fn cmd_resume(_args: &[String]) -> Status {
    eprintln!("ERROR: process::resume requires Windows");
    Status::Unsuccessful
}

/// Parse mimikatz-style named arguments: /name:value
#[cfg(windows)]
fn find_named_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let prefix = format!("/{}:", name);
    for arg in args {
        if let Some(val) = arg.strip_prefix(&prefix) {
            return Some(val);
        }
    }
    None
}
