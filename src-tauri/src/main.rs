//! authexodus Tauri shell. Batch 0 stub: opens the window and nothing else; package 2A adds
//! `session`, `commands`, `keychain` and `network` and registers the commands.
// Keep the console window out of the way on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod keychain;
mod network;
mod session;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .run(tauri::generate_context!())
        .expect("error while running authexodus");
}
