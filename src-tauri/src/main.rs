//! authexodus Tauri shell: holds one session's state and exposes the core to the UI as
//! commands and events matching `ui/src/api.ts`.
// Keep the console window out of the way on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod dto;
mod keychain;
mod network;
mod session;

use std::sync::Arc;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            app.manage(session::Session::new(
                Arc::new(keychain::KeychainStore),
                dir,
            ));
            Ok(())
        })
        .invoke_handler(commands::handler())
        .run(tauri::generate_context!())
        .expect("error while running authexodus");
}
