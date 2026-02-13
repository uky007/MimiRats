//! Module registry.
//!
//! Declares and registers all 25 command modules. The [`all_modules`] function
//! returns a static slice used by the REPL dispatcher in `main.rs`.

pub mod standard;
pub mod privilege;
pub mod token;
pub mod process;
pub mod sekurlsa;
pub mod lsadump;
pub mod kerberos;
pub mod crypto;
pub mod dpapi;
pub mod ngc;
pub mod service;
pub mod ts;
pub mod event;
pub mod misc;
pub mod vault;
pub mod minesweeper;
pub mod net;
pub mod busylight;
pub mod sysenv;
pub mod sid;
pub mod iis;
pub mod rpc;
pub mod sr98;
pub mod rdm;
pub mod acr;

use crate::module::Module;

static MODULES: [&Module; 25] = [
    &standard::MODULE,
    &privilege::MODULE,
    &token::MODULE,
    &process::MODULE,
    &sekurlsa::MODULE,
    &lsadump::MODULE,
    &kerberos::MODULE,
    &crypto::MODULE,
    &dpapi::MODULE,
    &ngc::MODULE,
    &service::MODULE,
    &ts::MODULE,
    &event::MODULE,
    &misc::MODULE,
    &vault::MODULE,
    &minesweeper::MODULE,
    &net::MODULE,
    &busylight::MODULE,
    &sysenv::MODULE,
    &sid::MODULE,
    &iis::MODULE,
    &rpc::MODULE,
    &sr98::MODULE,
    &rdm::MODULE,
    &acr::MODULE,
];

/// Returns all registered modules (maps to mimikatz_modules[] array).
pub fn all_modules() -> &'static [&'static Module] {
    &MODULES
}
