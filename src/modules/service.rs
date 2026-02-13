//! Service module — Windows Service Control Manager (SCM) operations.
//!
//! Provides commands for listing, starting, stopping, and managing Windows
//! services via the SCM API (`OpenSCManagerW`, `EnumServicesStatusExW`, etc.).

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "service",
    full_name: "Service module",
    description: "",
    commands: &COMMANDS,
    init: Some(init),
    clean: Some(clean),
};

fn init() -> Status { Status::Success }
fn clean() -> Status { Status::Success }

static COMMANDS: [Command; 9] = [
    Command { name: "start", description: "Start service", handler: cmd_start },
    Command { name: "remove", description: "Remove service", handler: cmd_remove },
    Command { name: "stop", description: "Stop service", handler: cmd_stop },
    Command { name: "suspend", description: "Suspend service", handler: cmd_suspend },
    Command { name: "resume", description: "Resume service", handler: cmd_resume },
    Command { name: "preshutdown", description: "Preshutdown service", handler: cmd_preshutdown },
    Command { name: "shutdown", description: "Shutdown service", handler: cmd_shutdown },
    Command { name: "list", description: "List services", handler: cmd_list },
    Command { name: "me", description: "Me!", handler: cmd_me },
];

// ---------------------------------------------------------------------------
// Windows implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    use windows::Win32::System::Services::*;
    use windows::core::*;
    use crate::module::Status;
    use crate::display::find_named_arg;

    /// Helper: encode a Rust &str to a null-terminated wide string.
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Open the Service Control Manager with the given access rights.
    unsafe fn open_scm(access: u32) -> Result<SC_HANDLE> {
        OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access)
    }

    /// Open a named service.  Caller must close both `scm` and the returned handle.
    unsafe fn open_service_by_name(
        scm: SC_HANDLE,
        name: &str,
        access: u32,
    ) -> Result<SC_HANDLE> {
        let wide = to_wide(name);
        OpenServiceW(scm, PCWSTR(wide.as_ptr()), access)
    }

    /// Generic helper that opens SCM + service, runs a closure, then closes handles.
    pub fn with_service<F>(args: &[String], scm_access: u32, svc_access: u32, action: F) -> Status
    where
        F: FnOnce(SC_HANDLE) -> Status,
    {
        let name = match find_named_arg(args, "name") {
            Some(n) => n,
            None => {
                eprintln!("ERROR: service name (/name:SvcName) is missing");
                return Status::Unsuccessful;
            }
        };

        unsafe {
            let scm = match open_scm(scm_access) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ERROR: OpenSCManager: {}", e);
                    return Status::Unsuccessful;
                }
            };

            let svc = match open_service_by_name(scm, name, svc_access) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ERROR: OpenService(\"{}\"): {}", name, e);
                    let _ = CloseServiceHandle(scm);
                    return Status::Unsuccessful;
                }
            };

            let result = action(svc);

            let _ = CloseServiceHandle(svc);
            let _ = CloseServiceHandle(scm);
            result
        }
    }

    /// Send a control code to a service.
    pub fn control_service(args: &[String], control: u32, control_name: &str) -> Status {
        with_service(
            args,
            SC_MANAGER_CONNECT,
            SERVICE_STOP
                | SERVICE_PAUSE_CONTINUE
                | SERVICE_INTERROGATE
                | SERVICE_USER_DEFINED_CONTROL,
            |svc| unsafe {
                let mut status = SERVICE_STATUS::default();
                match ControlService(svc, control, &mut status) {
                    Ok(()) => {
                        println!("{} of service : OK !", control_name);
                        Status::Success
                    }
                    Err(e) => {
                        eprintln!("ERROR: ControlService({}): {}", control_name, e);
                        Status::Unsuccessful
                    }
                }
            },
        )
    }

    pub fn cmd_start(args: &[String]) -> Status {
        with_service(
            args,
            SC_MANAGER_CONNECT,
            SERVICE_START,
            |svc| unsafe {
                match StartServiceW(svc, None) {
                    Ok(()) => {
                        println!("StartService : OK !");
                        Status::Success
                    }
                    Err(e) => {
                        eprintln!("ERROR: StartService: {}", e);
                        Status::Unsuccessful
                    }
                }
            },
        )
    }

    pub fn cmd_stop(args: &[String]) -> Status {
        control_service(args, SERVICE_CONTROL_STOP, "Stop")
    }

    pub fn cmd_suspend(args: &[String]) -> Status {
        control_service(args, SERVICE_CONTROL_PAUSE, "Suspend")
    }

    pub fn cmd_resume(args: &[String]) -> Status {
        control_service(args, SERVICE_CONTROL_CONTINUE, "Resume")
    }

    pub fn cmd_preshutdown(args: &[String]) -> Status {
        control_service(args, SERVICE_CONTROL_PRESHUTDOWN, "Preshutdown")
    }

    pub fn cmd_shutdown(args: &[String]) -> Status {
        control_service(args, SERVICE_CONTROL_SHUTDOWN, "Shutdown")
    }

    pub fn cmd_remove(args: &[String]) -> Status {
        with_service(
            args,
            SC_MANAGER_CONNECT,
            0x00010000u32, // DELETE standard access right
            |svc| unsafe {
                match DeleteService(svc) {
                    Ok(()) => {
                        println!("DeleteService : OK !");
                        Status::Success
                    }
                    Err(e) => {
                        eprintln!("ERROR: DeleteService: {}", e);
                        Status::Unsuccessful
                    }
                }
            },
        )
    }

    pub fn cmd_list(_args: &[String]) -> Status {
        unsafe {
            let scm = match open_scm(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ERROR: OpenSCManager: {}", e);
                    return Status::Unsuccessful;
                }
            };

            // First call: determine needed buffer size
            let mut bytes_needed: u32 = 0;
            let mut services_returned: u32 = 0;
            let mut resume_handle: u32 = 0;

            let _ = EnumServicesStatusExW(
                scm,
                SC_ENUM_TYPE(0), // SC_ENUM_PROCESS_INFO
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            );

            if bytes_needed == 0 {
                eprintln!("ERROR: EnumServicesStatusExW returned 0 bytes needed");
                let _ = CloseServiceHandle(scm);
                return Status::Unsuccessful;
            }

            // Second call: get actual data
            let mut buf = vec![0u8; bytes_needed as usize];
            resume_handle = 0;

            match EnumServicesStatusExW(
                scm,
                SC_ENUM_TYPE(0),
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            ) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("ERROR: EnumServicesStatusExW: {}", e);
                    let _ = CloseServiceHandle(scm);
                    return Status::Unsuccessful;
                }
            }

            let entries = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            );

            println!("{} services found\n", services_returned);
            for entry in entries {
                let name = entry.lpServiceName.to_string().unwrap_or_default();
                let display = entry.lpDisplayName.to_string().unwrap_or_default();
                let state = match entry.ServiceStatusProcess.dwCurrentState {
                    SERVICE_STOPPED => "STOPPED",
                    SERVICE_START_PENDING => "START_PENDING",
                    SERVICE_STOP_PENDING => "STOP_PENDING",
                    SERVICE_RUNNING => "RUNNING",
                    SERVICE_CONTINUE_PENDING => "CONTINUE_PENDING",
                    SERVICE_PAUSE_PENDING => "PAUSE_PENDING",
                    SERVICE_PAUSED => "PAUSED",
                    _ => "UNKNOWN",
                };
                println!("{:<40} {:>16}  {}", name, state, display);
            }

            let _ = CloseServiceHandle(scm);
        }
        Status::Success
    }

    pub fn cmd_me(_args: &[String]) -> Status {
        let pid = std::process::id();
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| String::from("(unknown)"));
        println!("PID   : {}", pid);
        println!("Image : {}", exe);
        Status::Success
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod win {
    use crate::module::Status;

    fn not_windows(name: &str) -> Status {
        eprintln!("ERROR: service::{} requires Windows", name);
        Status::Unsuccessful
    }

    pub fn cmd_start(_args: &[String]) -> Status { not_windows("start") }
    pub fn cmd_stop(_args: &[String]) -> Status { not_windows("stop") }
    pub fn cmd_suspend(_args: &[String]) -> Status { not_windows("suspend") }
    pub fn cmd_resume(_args: &[String]) -> Status { not_windows("resume") }
    pub fn cmd_preshutdown(_args: &[String]) -> Status { not_windows("preshutdown") }
    pub fn cmd_shutdown(_args: &[String]) -> Status { not_windows("shutdown") }
    pub fn cmd_remove(_args: &[String]) -> Status { not_windows("remove") }
    pub fn cmd_list(_args: &[String]) -> Status { not_windows("list") }

    pub fn cmd_me(_args: &[String]) -> Status {
        let pid = std::process::id();
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| String::from("(unknown)"));
        println!("PID   : {}", pid);
        println!("Image : {}", exe);
        Status::Success
    }
}

// ---------------------------------------------------------------------------
// Dispatch to platform-specific implementations
// ---------------------------------------------------------------------------

fn cmd_start(args: &[String]) -> Status { win::cmd_start(args) }
fn cmd_stop(args: &[String]) -> Status { win::cmd_stop(args) }
fn cmd_suspend(args: &[String]) -> Status { win::cmd_suspend(args) }
fn cmd_resume(args: &[String]) -> Status { win::cmd_resume(args) }
fn cmd_preshutdown(args: &[String]) -> Status { win::cmd_preshutdown(args) }
fn cmd_shutdown(args: &[String]) -> Status { win::cmd_shutdown(args) }
fn cmd_remove(args: &[String]) -> Status { win::cmd_remove(args) }
fn cmd_list(args: &[String]) -> Status { win::cmd_list(args) }
fn cmd_me(args: &[String]) -> Status { win::cmd_me(args) }
