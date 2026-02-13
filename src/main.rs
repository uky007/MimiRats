//! MimiRats — A Rust reimplementation of mimikatz.
//!
//! Provides a command-line interface with an interactive REPL and batch mode.
//! Commands follow the `module::command [/arg:value ...]` syntax.

mod module;
mod modules;
mod output;
mod win32;
mod crypto;
mod registry;
mod memory;
mod display;

use std::env;
use std::io::{self, Write};

use module::Status;
use modules::all_modules;

fn main() {
    mimikatz_begin();

    let args: Vec<String> = env::args().skip(1).collect();
    let mut status = Status::Success;

    // Process command-line arguments (like mimikatz's auto-command mode)
    for arg in &args {
        if status == Status::ProcessIsTerminating || status == Status::ThreadIsTerminating {
            break;
        }
        println!("\nMimiRats(commandline) # {}", arg);
        status = dispatch_command(arg);
    }

    // Interactive REPL loop
    let stdin = io::stdin();
    while status != Status::ProcessIsTerminating && status != Status::ThreadIsTerminating {
        print!("\nmimrats # ");
        io::stdout().flush().unwrap_or(());

        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        status = dispatch_command(input);
    }

    mimikatz_end();
}

fn mimikatz_begin() {
    output::print_banner();
    init_or_clean(true);
}

fn mimikatz_end() {
    init_or_clean(false);
}

fn init_or_clean(init: bool) {
    for module in all_modules() {
        let func = if init { module.init } else { module.clean };
        if let Some(f) = func {
            let status = f();
            if status != Status::Success {
                let phase = if init { "INIT" } else { "CLEAN" };
                eprintln!(
                    ">>> {} of '{}' module failed : {:?}",
                    phase, module.short_name, status
                );
            }
        }
    }
}

/// Dispatch a command string. Handles `!` (kernel), `*` (rpc), and local commands.
fn dispatch_command(input: &str) -> Status {
    let input = input.trim();
    if input.is_empty() {
        return Status::Unsuccessful;
    }

    match input.as_bytes()[0] {
        b'!' => {
            // Kernel operations - placeholder
            eprintln!("ERROR: kernel operations not yet implemented");
            Status::Unsuccessful
        }
        b'*' => {
            // RPC operations - placeholder
            eprintln!("ERROR: RPC operations not yet implemented");
            Status::Unsuccessful
        }
        _ => do_local(input),
    }
}

/// Parse and execute a local command. Supports `module::command [args...]` syntax.
fn do_local(input: &str) -> Status {
    let tokens = shell_split(input);
    if tokens.is_empty() {
        return Status::Success;
    }

    let (module_name, command_name) = parse_module_command(&tokens[0]);
    let args = &tokens[1..];

    let modules = all_modules();

    // Search for matching module and command
    for module in modules {
        let module_matches = match &module_name {
            Some(name) => module.short_name.eq_ignore_ascii_case(name),
            None => true, // no module specified: search all modules
        };

        if !module_matches {
            continue;
        }

        if let Some(cmd_name) = &command_name {
            if let Some(cmd) = module.find_command(cmd_name) {
                return (cmd.handler)(args);
            }
            // If module was explicitly specified but command not found, show help
            if module_name.is_some() {
                eprintln!(
                    "ERROR: \"{}\" command of \"{}\" module not found !",
                    cmd_name, module.short_name
                );
                print_module_help(module);
                return Status::Unsuccessful;
            }
        } else {
            // module specified but no command: show module help
            if module_name.is_some() {
                print_module_help(module);
                return Status::Success;
            }
        }
    }

    // Module not found
    if let Some(name) = &module_name {
        eprintln!("ERROR: \"{}\" module not found !", name);
        println!();
        for module in modules {
            print!("{:>16}", module.short_name);
            if !module.full_name.is_empty() {
                print!("  -  {}", module.full_name);
            }
            if !module.description.is_empty() {
                print!("  [{}]", module.description);
            }
            println!();
        }
    } else if let Some(cmd_name) = &command_name {
        eprintln!("ERROR: \"{}\" command not found in any module !", cmd_name);
    }

    Status::Unsuccessful
}

/// Parse `module::command` or just `command` from the first token.
fn parse_module_command(token: &str) -> (Option<String>, Option<String>) {
    if let Some(pos) = token.find("::") {
        let module = &token[..pos];
        let command = &token[pos + 2..];
        (
            if module.is_empty() {
                None
            } else {
                Some(module.to_string())
            },
            if command.is_empty() {
                None
            } else {
                Some(command.to_string())
            },
        )
    } else {
        (None, Some(token.to_string()))
    }
}

/// Simple shell-like argument splitting (handles quoted strings).
fn shell_split(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for ch in input.chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = true;
            quote_char = ch;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn print_module_help(module: &module::Module) {
    println!();
    print!("Module :\t{}", module.short_name);
    if !module.full_name.is_empty() {
        print!("\nFull name :\t{}", module.full_name);
    }
    if !module.description.is_empty() {
        print!("\nDescription :\t{}", module.description);
    }
    println!();
    for cmd in module.commands {
        print!("\n{:>16}", cmd.name);
        if !cmd.description.is_empty() {
            print!("  -  {}", cmd.description);
        }
    }
    println!();
}
