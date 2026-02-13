//! IIS module -- Parse IIS applicationHost.config for credentials.
//!
//! Reads the IIS configuration file (applicationHost.config) and extracts
//! connection strings, passwords, and credential information stored in
//! the configuration XML.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};
use crate::display;

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "iis",
    full_name: "IIS XML Config module",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 1] = [
    Command { name: "apphost", description: "IIS apphost.config passwords", handler: cmd_apphost },
];

// ===========================================================================
// Default IIS config path
// ===========================================================================

#[cfg(windows)]
const DEFAULT_APPHOST_PATH: &str = r"C:\Windows\System32\inetsrv\config\applicationHost.config";

#[cfg(not(windows))]
const DEFAULT_APPHOST_PATH: &str = "/etc/iis/applicationHost.config";

// ===========================================================================
// Pattern matching helpers (basic string-based XML extraction)
// ===========================================================================

/// Extract all values for a given attribute name from XML content.
/// Looks for patterns like: attributeName="value"
fn extract_attribute_values<'a>(content: &'a str, attr_name: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    let pattern = format!("{}=\"", attr_name);
    let mut search_from = 0;

    while let Some(start) = content[search_from..].find(&pattern) {
        let abs_start = search_from + start + pattern.len();
        if let Some(end) = content[abs_start..].find('"') {
            let value = &content[abs_start..abs_start + end];
            if !value.is_empty() {
                values.push(value);
            }
            search_from = abs_start + end + 1;
        } else {
            break;
        }
    }

    values
}

/// Extract content between XML tags. Finds all occurrences of <tag ...>...</tag>
/// or <tag ... /> and returns the full element text.
fn find_elements<'a>(content: &'a str, tag_name: &str) -> Vec<&'a str> {
    let mut elements = Vec::new();
    let open_tag = format!("<{}", tag_name);
    let mut search_from = 0;

    while let Some(start) = content[search_from..].find(&open_tag) {
        let abs_start = search_from + start;

        // Find the end of this element (either /> or </tagName>)
        let close_self = content[abs_start..].find("/>");
        let close_tag_pattern = format!("</{}>", tag_name);
        let close_pair = content[abs_start..].find(&close_tag_pattern);

        let end_offset = match (close_self, close_pair) {
            (Some(s), Some(p)) => {
                if s < p { s + 2 } else { p + close_tag_pattern.len() }
            }
            (Some(s), None) => s + 2,
            (None, Some(p)) => p + close_tag_pattern.len(),
            (None, None) => {
                search_from = abs_start + open_tag.len();
                continue;
            }
        };

        let element = &content[abs_start..abs_start + end_offset];
        elements.push(element);
        search_from = abs_start + end_offset;
    }

    elements
}

// ===========================================================================
// iis::apphost
// ===========================================================================

fn cmd_apphost(args: &[String]) -> Status {
    let path = display::find_named_arg(args, "in").unwrap_or(DEFAULT_APPHOST_PATH);

    println!("\nReading IIS applicationHost.config: {}\n", path);

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Failed to read '{}': {}", path, e);
            return Status::Unsuccessful;
        }
    };

    println!("  File size: {} bytes\n", content.len());

    let mut found_any = false;

    // 1. Search for <connectionStrings> entries
    let conn_strings = find_elements(&content, "add");
    let mut conn_count = 0;
    for element in &conn_strings {
        let connection_strings = extract_attribute_values(element, "connectionString");
        for cs in connection_strings {
            if cs.to_lowercase().contains("password") || cs.to_lowercase().contains("pwd") {
                conn_count += 1;
                println!("  [Connection String #{}]", conn_count);
                println!("    {}", cs);

                // Try to extract name
                let names = extract_attribute_values(element, "name");
                if let Some(name) = names.first() {
                    println!("    Name: {}", name);
                }
                println!();
                found_any = true;
            }
        }
    }

    // 2. Search for password attributes directly
    let passwords = extract_attribute_values(&content, "password");
    if !passwords.is_empty() {
        println!("  [Password attributes found]");
        for (i, pwd) in passwords.iter().enumerate() {
            if !pwd.is_empty() && *pwd != "[enc:...]" {
                println!("    [{}] password=\"{}\"", i, pwd);
                found_any = true;
            }
        }
        println!();
    }

    // 3. Search for userName attributes
    let usernames = extract_attribute_values(&content, "userName");
    if !usernames.is_empty() {
        println!("  [userName attributes found]");
        for (i, user) in usernames.iter().enumerate() {
            if !user.is_empty() {
                println!("    [{}] userName=\"{}\"", i, user);
                found_any = true;
            }
        }
        println!();
    }

    // 4. Search for processModel identity
    let process_models = find_elements(&content, "processModel");
    if !process_models.is_empty() {
        println!("  [Application Pool identities]");
        for element in &process_models {
            let users = extract_attribute_values(element, "userName");
            let pwds = extract_attribute_values(element, "password");
            let identity = extract_attribute_values(element, "identityType");

            if !users.is_empty() || !pwds.is_empty() {
                if let Some(id_type) = identity.first() {
                    print!("    Identity: {}", id_type);
                }
                if let Some(user) = users.first() {
                    print!("  User: {}", user);
                }
                if let Some(pwd) = pwds.first() {
                    print!("  Password: {}", pwd);
                }
                println!();
                found_any = true;
            }
        }
        println!();
    }

    // 5. Search for virtual directory credentials
    let vdirs = find_elements(&content, "virtualDirectory");
    for element in &vdirs {
        let users = extract_attribute_values(element, "userName");
        let pwds = extract_attribute_values(element, "password");
        let paths = extract_attribute_values(element, "physicalPath");

        if !users.is_empty() || !pwds.is_empty() {
            println!("  [Virtual Directory]");
            if let Some(path) = paths.first() {
                println!("    Path    : {}", path);
            }
            if let Some(user) = users.first() {
                println!("    User    : {}", user);
            }
            if let Some(pwd) = pwds.first() {
                println!("    Password: {}", pwd);
            }
            println!();
            found_any = true;
        }
    }

    if !found_any {
        println!("  No credentials found in configuration file.");
        println!("  (Passwords may be encrypted with IIS encryption or stored in separate files)");
    }

    Status::Success
}
