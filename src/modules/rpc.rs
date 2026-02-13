//! RPC module -- Remote Procedure Call server and client for MimiRats.
//!
//! Provides commands for starting an RPC server that accepts mimikatz
//! commands remotely, connecting to a remote RPC server, and enumerating
//! RPC endpoints on a target system.

#![allow(dead_code)]

use crate::module::{Command, Module, Status};

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

pub static MODULE: Module = Module {
    short_name: "rpc",
    full_name: "RPC control of mimikatz",
    description: "",
    commands: &COMMANDS,
    init: None,
    clean: None,
};

static COMMANDS: [Command; 3] = [
    Command { name: "server",  description: "Start or stop the RPC server",  handler: cmd_server },
    Command { name: "connect", description: "Connect to a RPC server",       handler: cmd_connect },
    Command { name: "enum",    description: "Enumerate RPC endpoints",       handler: cmd_enum },
];

// ===========================================================================
// rpc::server
// ===========================================================================

fn cmd_server(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: rpc::server not yet implemented");
    eprintln!("  This command starts (or stops) an RPC server that listens for");
    eprintln!("  mimikatz commands from remote clients.");
    eprintln!("  Requires:");
    eprintln!("    - RPC runtime library (rpcrt4.dll) for RpcServerUseProtseqEp");
    eprintln!("    - Custom RPC interface definition (IDL/ACF or manual stub)");
    eprintln!("    - Authentication: NTLM/Kerberos via RpcServerRegisterAuthInfo");
    eprintln!("    - Protocol: ncacn_ip_tcp or ncacn_np (named pipes)");
    eprintln!("  Usage:");
    eprintln!("    rpc::server /start -- start the RPC listener");
    eprintln!("    rpc::server /stop  -- stop the RPC listener");
    Status::Unsuccessful
}

// ===========================================================================
// rpc::connect
// ===========================================================================

fn cmd_connect(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: rpc::connect not yet implemented");
    eprintln!("  This command connects to a remote MimiRats RPC server and");
    eprintln!("  forwards commands for execution on the remote system.");
    eprintln!("  Requires:");
    eprintln!("    - RPC runtime library (rpcrt4.dll) for RpcStringBindingCompose");
    eprintln!("    - RpcBindingFromStringBinding + RpcBindingSetAuthInfo");
    eprintln!("    - Matching interface UUID from rpc::server");
    eprintln!("  Usage:");
    eprintln!("    rpc::connect /server:target.domain.local /port:1337");
    Status::Unsuccessful
}

// ===========================================================================
// rpc::enum
// ===========================================================================

fn cmd_enum(args: &[String]) -> Status {
    let _ = args;
    eprintln!("ERROR: rpc::enum not yet implemented");
    eprintln!("  This command enumerates RPC endpoints on a target system,");
    eprintln!("  similar to rpcdump.exe / rpcenum.");
    eprintln!("  Requires:");
    eprintln!("    - RPC runtime library for RpcMgmtEpEltInqBegin/Next");
    eprintln!("    - Binding to the endpoint mapper (port 135, ncacn_ip_tcp)");
    eprintln!("    - Iterating all registered interfaces and printing:");
    eprintln!("      - Interface UUID and version");
    eprintln!("      - Binding string (protocol, endpoint)");
    eprintln!("      - Annotation (description)");
    eprintln!("  Usage:");
    eprintln!("    rpc::enum /server:target.domain.local");
    Status::Unsuccessful
}
