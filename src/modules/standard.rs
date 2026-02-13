//! Standard module — built-in commands for MimiRats itself.
//!
//! Provides `exit`, `cls`, `version`, `answer`, `coffee`, `sleep`, and other
//! core commands that are always available.

use std::env;
use std::thread;
use std::time::Duration;

use chrono::Local;

use crate::module::{Command, Module, Status};
use crate::output;

pub static MODULE: Module = Module {
    short_name: "standard",
    full_name: "Standard module",
    description: "Basic commands (does not require module name)",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 8] = [
    Command {
        name: "exit",
        description: "Quit MimiRats",
        handler: cmd_exit,
    },
    Command {
        name: "cls",
        description: "Clear screen",
        handler: cmd_cls,
    },
    Command {
        name: "answer",
        description: "Answer to the Ultimate Question of Life, the Universe, and Everything",
        handler: cmd_answer,
    },
    Command {
        name: "coffee",
        description: "Please, make me a coffee!",
        handler: cmd_coffee,
    },
    Command {
        name: "sleep",
        description: "Sleep an amount of milliseconds",
        handler: cmd_sleep,
    },
    Command {
        name: "version",
        description: "Display some version information",
        handler: cmd_version,
    },
    Command {
        name: "cd",
        description: "Change or display current directory",
        handler: cmd_cd,
    },
    Command {
        name: "localtime",
        description: "Displays system local date and time (OJ command)",
        handler: cmd_localtime,
    },
];

fn cmd_exit(args: &[String]) -> Status {
    println!("Bye!");
    if args.is_empty() {
        Status::ProcessIsTerminating
    } else {
        Status::ThreadIsTerminating
    }
}

fn cmd_cls(_args: &[String]) -> Status {
    // ANSI escape: clear screen and move cursor to top-left
    print!("\x1B[2J\x1B[H");
    Status::Success
}

fn cmd_answer(_args: &[String]) -> Status {
    println!("42.");
    Status::Success
}

fn cmd_coffee(_args: &[String]) -> Status {
    println!();
    println!("    ( (");
    println!("     ) )");
    println!("  .______.");
    println!("  |      |]");
    println!("  \\      /");
    println!("   `----'");
    println!("    Coffee !");
    Status::Success
}

fn cmd_sleep(args: &[String]) -> Status {
    let ms: u64 = args
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    print!("Sleep : {} ms... ", ms);
    thread::sleep(Duration::from_millis(ms));
    println!("End !");
    Status::Success
}

fn cmd_version(_args: &[String]) -> Status {
    println!();
    println!(
        "MimiRats {} (arch {})",
        output::VERSION,
        output::ARCH
    );
    println!("{} {}", env::consts::OS, env::consts::ARCH);
    println!(
        "rustc (built with edition {})",
        env!("CARGO_PKG_RUST_VERSION", "unknown")
    );
    Status::Success
}

fn cmd_cd(args: &[String]) -> Status {
    match env::current_dir() {
        Ok(path) => {
            if !args.is_empty() {
                print!("Cur: ");
            }
            println!("{}", path.display());
        }
        Err(e) => {
            eprintln!("ERROR: current_dir: {}", e);
        }
    }
    if let Some(dir) = args.first() {
        if let Err(e) = env::set_current_dir(dir) {
            eprintln!("ERROR: set_current_dir: {}", e);
        } else {
            match env::current_dir() {
                Ok(path) => println!("New: {}", path.display()),
                Err(e) => eprintln!("ERROR: current_dir: {}", e),
            }
        }
    }
    Status::Success
}

fn cmd_localtime(_args: &[String]) -> Status {
    let now = Local::now();
    println!("Local: {}", now.format("%Y/%m/%d %H:%M:%S"));
    println!("UTC  : {}", now.to_utc().format("%Y/%m/%d %H:%M:%S"));
    Status::Success
}
