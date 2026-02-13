//! Banner and version output.
//!
//! Contains version constants, architecture detection, and the startup banner.

/// MimiRats version string.
pub const VERSION: &str = "0.1.0";
/// Build codename (matches mimikatz tradition).
pub const CODENAME: &str = "A La Vie, A L'Amour";

/// Target architecture identifier.
#[cfg(target_arch = "x86_64")]
pub const ARCH: &str = "x64";
/// Target architecture identifier.
#[cfg(target_arch = "x86")]
pub const ARCH: &str = "x86";
/// Target architecture identifier.
#[cfg(target_arch = "aarch64")]
pub const ARCH: &str = "arm64";
/// Target architecture identifier.
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
pub const ARCH: &str = "unknown";

/// Print the MimiRats startup banner to stdout.
pub fn print_banner() {
    println!();
    println!("  .#####.   MimiRats {} ({}) - Rust edition", VERSION, ARCH);
    println!(" .## ^ ##.  \"{}\"", CODENAME);
    println!(" ## / \\ ##  A Rust reimplementation of mimikatz");
    println!(" ## \\ / ##       > Original by Benjamin DELPY `gentilkiwi`");
    println!(" '## v ##'       > https://blog.gentilkiwi.com/mimikatz");
    println!("  '#####'        (oe.eo)");
}
