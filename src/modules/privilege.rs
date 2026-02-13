//! Privilege module — Windows token privilege manipulation.
//!
//! Enables or adjusts process token privileges such as `SeDebugPrivilege`,
//! used as a prerequisite for accessing LSASS and other protected resources.

use crate::module::{Command, Module, Status};

pub static MODULE: Module = Module {
    short_name: "privilege",
    full_name: "Privilege module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 9] = [
    Command {
        name: "debug",
        description: "Ask debug privilege",
        handler: cmd_debug,
    },
    Command {
        name: "driver",
        description: "Ask load driver privilege",
        handler: cmd_driver,
    },
    Command {
        name: "security",
        description: "Ask security privilege",
        handler: cmd_security,
    },
    Command {
        name: "tcb",
        description: "Ask tcb privilege",
        handler: cmd_tcb,
    },
    Command {
        name: "backup",
        description: "Ask backup privilege",
        handler: cmd_backup,
    },
    Command {
        name: "restore",
        description: "Ask restore privilege",
        handler: cmd_restore,
    },
    Command {
        name: "sysenv",
        description: "Ask system environment privilege",
        handler: cmd_sysenv,
    },
    Command {
        name: "id",
        description: "Ask a privilege by its id",
        handler: cmd_id,
    },
    Command {
        name: "name",
        description: "Ask a privilege by its name",
        handler: cmd_name,
    },
];

#[cfg(windows)]
fn privilege_simple(priv_id: u32) -> Status {
    match crate::win32::api::adjust_privilege_by_id(priv_id) {
        Ok(()) => {
            println!("Privilege '{}' OK", priv_id);
            Status::Success
        }
        Err(e) => {
            eprintln!("ERROR: RtlAdjustPrivilege ({}) {}", priv_id, e);
            Status::Unsuccessful
        }
    }
}

#[cfg(not(windows))]
fn privilege_simple(priv_id: u32) -> Status {
    eprintln!("ERROR: privilege operations require Windows (id: {})", priv_id);
    Status::Unsuccessful
}

fn cmd_debug(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_DEBUG) }
    #[cfg(not(windows))]
    { privilege_simple(20) }
}

fn cmd_driver(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_LOAD_DRIVER) }
    #[cfg(not(windows))]
    { privilege_simple(10) }
}

fn cmd_security(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_SECURITY) }
    #[cfg(not(windows))]
    { privilege_simple(8) }
}

fn cmd_tcb(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_TCB) }
    #[cfg(not(windows))]
    { privilege_simple(7) }
}

fn cmd_backup(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_BACKUP) }
    #[cfg(not(windows))]
    { privilege_simple(17) }
}

fn cmd_restore(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_RESTORE) }
    #[cfg(not(windows))]
    { privilege_simple(18) }
}

fn cmd_sysenv(_args: &[String]) -> Status {
    #[cfg(windows)]
    { privilege_simple(crate::win32::api::SE_SYSTEM_ENVIRONMENT) }
    #[cfg(not(windows))]
    { privilege_simple(22) }
}

fn cmd_id(args: &[String]) -> Status {
    match args.first().and_then(|s| s.parse::<u32>().ok()) {
        Some(id) => privilege_simple(id),
        None => {
            eprintln!("ERROR: Missing 'id'");
            Status::Unsuccessful
        }
    }
}

fn cmd_name(args: &[String]) -> Status {
    match args.first() {
        Some(name) => {
            #[cfg(windows)]
            {
                match crate::win32::api::adjust_privilege_by_name(name) {
                    Ok(()) => {
                        println!("Privilege '{}' OK", name);
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
                eprintln!("ERROR: privilege operations require Windows (name: {})", name);
                Status::Unsuccessful
            }
        }
        None => {
            eprintln!("ERROR: Missing 'name'");
            Status::Unsuccessful
        }
    }
}
