//! authexodus Tauri shell: holds one session's state and exposes the core to the UI as
//! commands and events matching `ui/src/api.ts`.

pub mod awake;
pub mod commands;
pub mod dto;
pub mod errors;
pub mod keychain;
pub mod logging;
pub mod network;
pub mod progress;
pub mod session;

use std::path::Path;
use std::sync::Arc;

use tauri::{Manager, RunEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

/// The label of the app's one window (Tauri's default, and the one the capability names).
const MAIN_WINDOW: &str = "main";

/// Shown in a system dialog, as it is written here, when the app cannot make or use its own
/// data folder at launch. There is no window to say it in: the app closes when the dialog is
/// dismissed.
pub const SETUP_FAILED: &str = "authexodus could not start, because it could not create or open its own folder in your Library's Application Support folder. Check that this computer's disk is not full and that your user account can write to its Library folder, then open authexodus again.";

/// Make the app's data folder, for its owner only.
fn prepare_data_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn run() {
    // Before anything else, so that every stage of the run can be followed from Terminal.
    logging::init();
    match logging::raise_open_file_limit() {
        Some(limit) => tracing::debug!(limit, "open-file limit"),
        None => tracing::warn!("the open-file limit could not be read"),
    }
    let built = tauri::Builder::default()
        // First, as the plugin asks: a second copy of the app stops here, before it has
        // touched anything the first copy owns (the keychain item, the marker, the Bitwarden
        // folders), and the first copy's window comes forward instead.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tracing::info!("a second copy was opened; bringing this one forward");
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let prepared = app
                .path()
                .app_data_dir()
                .map_err(|_| std::io::ErrorKind::NotFound)
                .and_then(|dir| prepare_data_dir(&dir).map(|()| dir).map_err(|e| e.kind()));
            match prepared {
                Ok(dir) => {
                    app.manage(session::Session::new(
                        Arc::new(keychain::KeychainStore),
                        dir,
                    ));
                }
                Err(kind) => {
                    // Not a panic and not a window that cannot work: say why in a system
                    // dialog, then leave. (The dialog is shown once the event loop runs,
                    // which is why this returns normally.)
                    tracing::error!(?kind, "the app's data folder could not be prepared");
                    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                        let _ = window.hide();
                    }
                    let handle = app.handle().clone();
                    app.dialog()
                        .message(SETUP_FAILED)
                        .title("authexodus")
                        .kind(MessageDialogKind::Error)
                        .show(move |_| handle.exit(1));
                }
            }
            Ok(())
        })
        .invoke_handler(commands::handler())
        .build(tauri::generate_context!());
    let app = match built {
        Ok(app) => app,
        Err(error) => {
            // Nothing of Tauri is running, so there is nothing to show a dialog with; the
            // reason goes to the log and the exit status says it failed.
            tracing::error!(
                error = %logging::sanitised(&error.to_string()),
                "the app could not be started"
            );
            std::process::exit(1);
        }
    };

    app.run(|handle, event| {
        // Closing the window mid-flow: stop listening on the network (and stop keeping the
        // computer awake) and remove what Bitwarden left on disk. The certificate key and
        // the marker stay, so the next launch opens on cleanup. Both events can arrive for
        // one exit; doing it twice is harmless.
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

    #[cfg(unix)]
    #[test]
    fn the_data_folder_is_made_for_its_owner_only_and_a_failure_is_an_error_not_a_panic() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("Application Support").join("authexodus");
        super::prepare_data_dir(&data).unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        super::prepare_data_dir(&data).expect("a folder that is already there is fine");

        // Something that is not a folder is in the way: reported, for the dialog to say.
        std::fs::write(dir.path().join("blocked"), b"a file").unwrap();
        assert!(super::prepare_data_dir(&dir.path().join("blocked").join("authexodus")).is_err());
    }

    #[test]
    fn what_the_person_is_told_when_the_app_cannot_start_is_plain() {
        let said = super::SETUP_FAILED;
        assert!(said.starts_with("authexodus could not start"));
        assert!(said.ends_with('.'));
        for mark in ['/', '\\', '{', '}', '~'] {
            assert!(!said.contains(mark), "{mark:?} in {said}");
        }
        for jargon in ["error", "panic", "directory", "permission denied"] {
            assert!(
                !said.to_lowercase().contains(jargon),
                "{jargon:?} in {said}"
            );
        }
    }

    /// The value of `key` in the Info.plist additions, if it is there as a string.
    fn plist_string<'a>(plist: &'a str, key: &str) -> Option<&'a str> {
        let after = plist.split_once(&format!("<key>{key}</key>"))?.1;
        let value = after.trim_start().strip_prefix("<string>")?;
        Some(value.split_once("</string>")?.0)
    }

    #[test]
    fn the_local_network_prompt_says_why_in_plain_words() {
        let plist = include_str!("../Info.plist");
        let said = plist_string(plist, "NSLocalNetworkUsageDescription")
            .expect("the local-network usage description is set");
        assert_eq!(
            said,
            "authexodus lets your iPhone or iPad connect to this Mac over your Wi-Fi so it can read the backup Authy sends."
        );
        // Tauri finds the file by its name and place: beside tauri.conf.json. The
        // configuration must not point somewhere else.
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert!(config["bundle"]["macOS"].get("infoPlist").is_none());
        assert!(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/Info.plist")).exists()
                && std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json"))
                    .exists()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_info_plist_additions_are_a_well_formed_property_list() {
        let checked = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Info.plist"))
            .output()
            .expect("plutil is part of macOS");
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stdout)
        );
    }

    /// The `version = "..."` of a `[section]` in a Cargo manifest.
    fn manifest_version(manifest: &str, section: &str) -> Option<String> {
        let body = manifest.split_once(&format!("[{section}]"))?.1;
        let body = body.split("\n[").next()?;
        body.lines().find_map(|line| {
            let value = line.trim().strip_prefix("version")?.trim_start();
            let value = value.strip_prefix('=')?.trim();
            Some(value.trim_matches('"').to_string())
        })
    }

    /// The version the app shows comes from Cargo; the bundle's from `tauri.conf.json`; the
    /// workspace's and the UI's from their `package.json`. A release must not ship with any
    /// two of them apart. (The release workflow makes the same comparison against the tag.)
    #[test]
    fn the_version_is_the_same_everywhere_it_is_written() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        let read = |path: &str| std::fs::read_to_string(format!("{root}/{path}")).ok();
        let json_version = |path: &str| -> Option<String> {
            let value: serde_json::Value = serde_json::from_str(&read(path)?).ok()?;
            Some(value["version"].as_str()?.to_string())
        };

        let shown = env!("CARGO_PKG_VERSION").to_string();
        let bundle = json_version("src-tauri/tauri.conf.json").expect("tauri.conf.json");
        assert_eq!(
            bundle, shown,
            "tauri.conf.json and the version the app shows"
        );

        // The shell and the core take theirs from the workspace, so there is one in Cargo.
        let workspace = read("Cargo.toml").expect("the workspace manifest");
        assert_eq!(
            manifest_version(&workspace, "workspace.package").as_deref(),
            Some(shown.as_str())
        );
        for manifest in ["src-tauri/Cargo.toml", "crates/core/Cargo.toml"] {
            let text = read(manifest).unwrap();
            assert!(
                text.contains("version.workspace = true"),
                "{manifest} must take its version from the workspace"
            );
        }

        // Where present (a source checkout always has both).
        for package in ["package.json", "ui/package.json"] {
            if let Some(version) = json_version(package) {
                assert_eq!(version, shown, "{package}");
            }
        }
        assert!(json_version("package.json").is_some());
        assert!(json_version("ui/package.json").is_some());
    }

    #[test]
    fn the_release_workflow_checks_the_tag_against_every_place_the_version_is_written() {
        let workflow = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../.github/workflows/release.yml"
        ))
        .unwrap();
        let step = workflow
            .split_once("- name: The tag must match the version everywhere it is written")
            .expect("the step is there")
            .1;
        let step = step.split("\n      - ").next().unwrap();
        for place in [
            "src-tauri/tauri.conf.json",
            "package.json",
            "ui/package.json",
            "cargo metadata",
            "authexodus",
            "authexodus-core",
            "GITHUB_REF_NAME",
        ] {
            assert!(step.contains(place), "the tag check does not cover {place}");
        }
    }

    #[test]
    fn the_app_has_one_window_and_it_is_the_one_a_second_launch_brings_forward() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let windows = config["app"]["windows"].as_array().unwrap();
        assert_eq!(windows.len(), 1);
        // Tauri names a window "main" unless told otherwise.
        let label = windows[0]["label"].as_str().unwrap_or("main");
        assert_eq!(label, super::MAIN_WINDOW);
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(
            capability["windows"],
            serde_json::json!([super::MAIN_WINDOW])
        );
    }

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
