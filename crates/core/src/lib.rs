//! authexodus core. No Tauri dependency: everything sensitive is testable from `cargo test`.
//! This file declares modules only; each module is owned by one work package (see the plan).

pub mod backup;
pub mod bitwarden;
pub mod ca;
pub mod capture;
pub mod export;
pub mod proxy;
pub mod totp;
pub mod types;
