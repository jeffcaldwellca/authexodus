//! authexodus: the desktop app. Everything lives in the library (`lib.rs`), so the tests can
//! drive it without a window.
// Keep the console window out of the way on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    authexodus_lib::run();
}
