//! authexodus Tauri shell: holds one session's state and exposes the core to the UI as
//! commands and events matching `ui/src/api.ts`.

pub mod commands;
pub mod dto;
pub mod keychain;
pub mod logging;
pub mod network;
pub mod session;

use std::sync::Arc;

use tauri::{Manager, RunEvent};

pub fn run() {
    // Before anything else, so that every stage of the run can be followed from Terminal.
    logging::init();
    match logging::raise_open_file_limit() {
        Some(limit) => tracing::debug!(limit, "open-file limit"),
        None => tracing::warn!("the open-file limit could not be read"),
    }
    let app = tauri::Builder::default()
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
        .build(tauri::generate_context!())
        .expect("error while building authexodus");

    app.run(|handle, event| {
        // Closing the window mid-flow: stop listening on the network and remove what Bitwarden
        // left on disk. The certificate key and the marker stay, so the next launch opens on
        // cleanup. Both events can arrive for one exit; doing it twice is harmless.
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            if let Some(session) = handle.try_state::<session::Session>() {
                session.on_exit();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    /// A policy as `directive -> sources`.
    fn directives(policy: &str) -> BTreeMap<&str, Vec<&str>> {
        policy
            .split(';')
            .filter_map(|d| {
                let mut words = d.split_whitespace();
                Some((words.next()?, words.collect()))
            })
            .collect()
    }

    fn security() -> serde_json::Value {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        config["app"]["security"].clone()
    }

    #[test]
    fn the_window_runs_under_a_strict_content_security_policy() {
        let security = security();
        let policy = security["csp"]
            .as_str()
            .expect("a content security policy is set");
        let csp = directives(policy);

        // Only the app's own files by default, and scripts from nowhere else: no inline
        // script, no eval, no remote origin.
        assert_eq!(csp["default-src"], ["'self'"]);
        assert_eq!(csp["script-src"], ["'self'"]);
        assert_eq!(csp["object-src"], ["'none'"]);
        assert_eq!(csp["form-action"], ["'none'"]);
        // The app talks to its own core over Tauri's IPC and to nothing else.
        assert_eq!(csp["connect-src"], ["ipc:", "http://ipc.localhost"]);
        // QR codes are drawn as `data:` images.
        assert_eq!(csp["img-src"], ["'self'", "data:"]);
        for (directive, sources) in &csp {
            for source in sources {
                assert!(
                    !source.contains("unsafe-eval") && !source.contains('*'),
                    "{directive} {source}"
                );
                assert!(
                    !source.starts_with("https:") && !source.starts_with("http:")
                        || *source == "http://ipc.localhost",
                    "{directive} allows a remote origin: {source}"
                );
            }
        }
    }

    #[test]
    fn the_dev_policy_only_adds_what_the_dev_server_needs() {
        let security = security();
        let dev = directives(security["devCsp"].as_str().expect("a dev policy is set"));
        assert_eq!(dev["default-src"], ["'self'"]);
        assert_eq!(
            dev["connect-src"],
            [
                "ipc:",
                "http://ipc.localhost",
                "http://localhost:1420",
                "ws://localhost:1420"
            ],
            "IPC, plus the dev server and its hot-reload socket"
        );
        // The dev server's React refresh preamble is an inline script.
        assert_eq!(dev["script-src"], ["'self'", "'unsafe-inline'"]);
        assert!(!security["devCsp"].as_str().unwrap().contains("unsafe-eval"));
    }
}
