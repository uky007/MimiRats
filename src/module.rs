//! Core module and command type definitions.
//!
//! Defines [`Module`], [`Command`], and [`Status`] — the building blocks
//! of the MimiRats module system, corresponding to mimikatz's `KUHL_M`,
//! `KUHL_M_C`, and `NTSTATUS` types.

/// NTSTATUS equivalent for MimiRats.
/// Maps to the original mimikatz status codes used for control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    Unsuccessful,
    /// Signals the REPL to exit the entire process (normal exit).
    ProcessIsTerminating,
    /// Signals the REPL to exit the current thread (exit with args).
    ThreadIsTerminating,
}

/// A single command within a module (maps to KUHL_M_C).
pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub handler: fn(args: &[String]) -> Status,
}

/// A module grouping related commands (maps to KUHL_M).
pub struct Module {
    pub short_name: &'static str,
    pub full_name: &'static str,
    pub description: &'static str,
    pub commands: &'static [Command],
    pub init: Option<fn() -> Status>,
    pub clean: Option<fn() -> Status>,
}

impl Module {
    /// Find a command by name (case-insensitive).
    pub fn find_command(&self, name: &str) -> Option<&Command> {
        self.commands
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }
}
