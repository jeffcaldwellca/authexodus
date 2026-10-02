//! Tauri commands, one per method of `ui/src/api.ts` (package 2A).
//!
//! # Naming convention
//!
//! * A method of `Api` becomes a command named by its **snake_case** form, which is the Rust
//!   function name Tauri registers: `getState` -> `get_state`, `bwLogin` -> `bw_login`,
//!   `googleMigrationQrs` -> `google_migration_qrs`. The UI calls `invoke("bw_login", { login })`;
//!   Tauri maps argument names from camelCase on the JavaScript side, so the argument names are
//!   the ones in `api.ts` (`ip`, `password`, `login`, `decisions`, ...).
//! * The two `on*` methods are not commands. They are events, named in kebab-case without the
//!   `on` prefix and the `Event` suffix: `onProxyEvent` -> `proxy-event`,
//!   `onBwProgress` -> `bw-progress` (see [`EVENTS`]).
//! * Payloads and results serialise to the TypeScript shapes exactly (see `dto.rs`).
//! * A failed command rejects with a plain-language string that never contains a password or a
//!   secret. No command logs its arguments; `unlock` and `bwLogin` carry passwords.
//!
//! The command list is written once, in `commands!`, which also builds the Tauri handler, so
//! `commands_match_api_contract` compares the real registered list against `api.ts`.

use std::path::PathBuf;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::dto::*;
use crate::network;
use crate::session::{write_owner_only, EmitProgress, EmitProxy, Session};
use authexodus_core::export::ExportFile;

/// `Api.onProxyEvent` / `Api.onBwProgress`, as `(method, event name)`.
#[cfg_attr(not(test), allow(dead_code))]
pub const EVENTS: &[(&str, &str)] = &[
    ("onProxyEvent", EVENT_PROXY),
    ("onBwProgress", EVENT_BW_PROGRESS),
];
pub const EVENT_PROXY: &str = "proxy-event";
pub const EVENT_BW_PROGRESS: &str = "bw-progress";

#[tauri::command]
pub fn get_state(session: State<'_, Session>) -> AppState {
    session.get_state()
}

#[tauri::command]
pub fn set_device(session: State<'_, Session>, device: Device) {
    session.set_device(device);
}

#[tauri::command]
pub async fn start_proxy(
    app: AppHandle,
    session: State<'_, Session>,
    ip: Option<String>,
) -> Result<ProxyInfo, CmdError> {
    let emit: EmitProxy = Arc::new(move |event| {
        let _ = app.emit(EVENT_PROXY, event);
    });
    session
        .start_proxy(ip.as_deref(), &network::system_candidates(), emit)
        .await
}

#[tauri::command]
pub async fn unlock(
    session: State<'_, Session>,
    password: String,
) -> Result<UnlockResult, CmdError> {
    session.unlock(&password).await
}

#[tauri::command]
pub fn token_qr(session: State<'_, Session>, id: String) -> Result<String, CmdError> {
    session.token_qr(&id)
}

#[tauri::command]
pub fn google_migration_qrs(session: State<'_, Session>) -> Result<Vec<String>, CmdError> {
    session.google_migration_qrs()
}

/// Write `file` to `chosen` (owner-only), or report that the person cancelled.
pub fn finish_export(
    file: &ExportFile,
    chosen: Option<PathBuf>,
) -> Result<ExportOutcome, CmdError> {
    let Some(path) = chosen else {
        return Ok(ExportOutcome::Cancelled { cancelled: true });
    };
    write_owner_only(&path, &file.bytes)
        .map_err(|e| CmdError::new(format!("could not save the file: {e}")))?;
    Ok(ExportOutcome::Saved {
        saved: path.to_string_lossy().into_owned(),
    })
}

/// The save dialog is opened from Rust, so the webview needs no `dialog:` permission.
#[tauri::command]
pub async fn export_file(
    app: AppHandle,
    window: WebviewWindow,
    session: State<'_, Session>,
    dest: DestinationDto,
) -> Result<ExportOutcome, CmdError> {
    let file = session.prepare_export(dest)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_parent(&window)
        .set_file_name(&file.suggested_name)
        .save_file(move |picked| {
            let _ = tx.send(picked);
        });
    let picked = rx
        .await
        .map_err(|_| CmdError::new("the save dialog closed unexpectedly"))?;
    let chosen = match picked {
        None => None,
        Some(p) => Some(
            p.into_path()
                .map_err(|_| CmdError::new("that location cannot be saved to"))?,
        ),
    };
    finish_export(&file, chosen)
}

#[tauri::command]
pub fn live_codes(session: State<'_, Session>) -> Result<Vec<LiveCode>, CmdError> {
    session.live_codes()
}

#[tauri::command]
pub async fn bw_prepare(session: State<'_, Session>) -> Result<(), CmdError> {
    session.bw_prepare().await
}

#[tauri::command]
pub async fn bw_login(
    session: State<'_, Session>,
    login: BwLoginInput,
) -> Result<BwLoginResult, CmdError> {
    let client = session.new_cli_client()?;
    session.bw_login(Box::new(client), login).await
}

#[tauri::command]
pub async fn bw_propose(session: State<'_, Session>) -> Result<Vec<ProposalDto>, CmdError> {
    session.bw_propose().await
}

#[tauri::command]
pub async fn bw_apply(
    app: AppHandle,
    session: State<'_, Session>,
    decisions: Vec<DecisionEntry>,
) -> Result<ApplyReportDto, CmdError> {
    let progress: EmitProgress = Arc::new(move |line| {
        let _ = app.emit(EVENT_BW_PROGRESS, line);
    });
    session.bw_apply(decisions, progress).await
}

#[tauri::command]
pub async fn cleanup(session: State<'_, Session>) -> Result<(), CmdError> {
    session.cleanup().await
}

#[tauri::command]
pub async fn finish(session: State<'_, Session>) -> Result<(), CmdError> {
    session.finish().await
}

/// The single list of commands: it builds both the handler Tauri registers and
/// [`COMMAND_NAMES`], so the two cannot differ.
macro_rules! commands {
    ($($name:ident),+ $(,)?) => {
        #[cfg_attr(not(test), allow(dead_code))]
        pub const COMMAND_NAMES: &[&str] = &[$(stringify!($name)),+];

        pub fn handler() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
            tauri::generate_handler![$($name),+]
        }
    };
}

commands!(
    get_state,
    set_device,
    start_proxy,
    unlock,
    token_qr,
    google_migration_qrs,
    export_file,
    live_codes,
    bw_prepare,
    bw_login,
    bw_propose,
    bw_apply,
    cleanup,
    finish,
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn snake(camel: &str) -> String {
        let mut out = String::new();
        for c in camel.chars() {
            if c.is_ascii_uppercase() {
                out.push('_');
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Method names of `interface Api { ... }`, in order.
    fn api_methods() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../ui/src/api.ts");
        let src = std::fs::read_to_string(path).expect("ui/src/api.ts is in the repository");
        let start = src
            .find("export interface Api {")
            .expect("api.ts declares `export interface Api`");
        let body = &src[start..];
        let end = body.find("\n}").expect("the Api interface is closed");
        body["export interface Api {".len()..end]
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                let name: String = line
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!name.is_empty() && line[name.len()..].starts_with('(')).then_some(name)
            })
            .collect()
    }

    #[test]
    fn commands_match_api_contract() {
        let methods = api_methods();
        assert!(methods.len() >= 16, "parsed too few methods: {methods:?}");

        let (event_methods, command_methods): (Vec<_>, Vec<_>) =
            methods.iter().partition(|m| m.starts_with("on"));

        // Every command-shaped method is a registered command, and nothing else is.
        let expected: BTreeSet<String> = command_methods.iter().map(|m| snake(m)).collect();
        let registered: BTreeSet<String> = COMMAND_NAMES.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            registered, expected,
            "registered commands differ from the methods of `Api` in ui/src/api.ts"
        );
        assert_eq!(
            COMMAND_NAMES.len(),
            registered.len(),
            "a command is listed twice"
        );

        // Every `on*` method is a known event, and every event has a method.
        let known: BTreeSet<&str> = EVENTS.iter().map(|(m, _)| *m).collect();
        let on: BTreeSet<&str> = event_methods.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            on, known,
            "`on*` methods of `Api` differ from the events in commands.rs"
        );
    }

    #[test]
    fn snake_case_mapping_examples() {
        assert_eq!(snake("getState"), "get_state");
        assert_eq!(snake("bwLogin"), "bw_login");
        assert_eq!(snake("googleMigrationQrs"), "google_migration_qrs");
        assert_eq!(snake("cleanup"), "cleanup");
    }

    #[test]
    fn export_outcomes_serialise_to_the_ui_union() {
        let file = ExportFile {
            suggested_name: "x.csv".into(),
            bytes: b"a,b".to_vec(),
        };
        let cancelled = finish_export(&file, None).unwrap();
        assert_eq!(
            serde_json::to_string(&cancelled).unwrap(),
            r#"{"cancelled":true}"#
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.csv");
        let saved = finish_export(&file, Some(path.clone())).unwrap();
        assert_eq!(
            serde_json::to_value(&saved).unwrap(),
            serde_json::json!({ "saved": path.to_string_lossy() })
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"a,b");
    }

    #[test]
    fn app_state_and_proxy_info_serialise_camel_case() {
        let s = AppState {
            step: Step::Welcome,
            device: Some(Device::Iphone),
            resume_cleanup: false,
            version: "0.1.0".into(),
        };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"step":"welcome","device":"iphone","resumeCleanup":false,"version":"0.1.0"}"#
        );
        let none = AppState { device: None, ..s };
        assert!(serde_json::to_string(&none)
            .unwrap()
            .contains(r#""device":null"#));
        let info = ProxyInfo {
            addresses: vec![AddressView {
                ip: "1.2.3.4".into(),
                label: "Wi-Fi".into(),
            }],
            ip: "1.2.3.4".into(),
            port: 8080,
            cert_url: "http://1.2.3.4:8080/".into(),
            cert_qr_svg: "<svg/>".into(),
            check_url: "https://c/".into(),
        };
        let v = serde_json::to_value(&info).unwrap();
        for k in [
            "addresses",
            "ip",
            "port",
            "certUrl",
            "certQrSvg",
            "checkUrl",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        let code = serde_json::to_value(LiveCode {
            id: "1".into(),
            code: "123456".into(),
            seconds_left: 9,
        })
        .unwrap();
        assert_eq!(code["secondsLeft"], 9);
        assert_eq!(
            serde_json::to_string(&Step::Certificate).unwrap(),
            r#""certificate""#
        );
    }

    #[test]
    fn destinations_deserialise_from_the_ui_strings() {
        for d in [
            "bitwarden",
            "onePassword",
            "twoFas",
            "aegis",
            "googleAuthenticator",
            "protonAuthenticator",
            "plainText",
        ] {
            serde_json::from_str::<DestinationDto>(&format!("\"{d}\"")).unwrap();
        }
    }
}
