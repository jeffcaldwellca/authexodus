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
//!   secret. No command logs its arguments; `unlock` and `bwLogin` carry passwords, which are
//!   held in `Zeroizing` so they are wiped from memory when the command is done.
//!
//! The command list is written once, in `commands!`, which also builds the Tauri handler, so
//! `commands_match_api_contract` compares the real registered list against `api.ts`. It also
//! reads this file and compares each command's argument names with the method's parameters.

use std::path::PathBuf;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

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

fn proxy_emitter(app: AppHandle) -> EmitProxy {
    Arc::new(move |event| {
        let _ = app.emit(EVENT_PROXY, event);
    })
}

/// Idempotent: see [`Session::start_proxy`].
#[tauri::command]
pub async fn start_proxy(
    app: AppHandle,
    session: State<'_, Session>,
    ip: Option<String>,
) -> Result<ProxyInfo, CmdError> {
    session
        .start_proxy(ip.as_deref(), &network::system(), proxy_emitter(app))
        .await
}

/// The explicit start-over: see [`Session::restart_proxy`].
#[tauri::command]
pub async fn restart_proxy(
    app: AppHandle,
    session: State<'_, Session>,
    ip: Option<String>,
) -> Result<ProxyInfo, CmdError> {
    session
        .restart_proxy(ip.as_deref(), &network::system(), proxy_emitter(app))
        .await
}

#[tauri::command]
pub async fn unlock(
    session: State<'_, Session>,
    password: Zeroizing<String>,
) -> Result<UnlockResult, CmdError> {
    session.unlock(password).await
}

#[tauri::command]
pub fn token_qr(session: State<'_, Session>, id: String) -> Result<String, CmdError> {
    session.token_qr(&id)
}

#[tauri::command]
pub fn google_migration_qrs(session: State<'_, Session>) -> Result<Vec<String>, CmdError> {
    session.google_migration_qrs()
}

#[tauri::command]
pub fn google_unsupported(session: State<'_, Session>) -> Result<Vec<String>, CmdError> {
    session.google_unsupported()
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
    restart_proxy,
    unlock,
    token_qr,
    google_migration_qrs,
    google_unsupported,
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

    fn camel(snake: &str) -> String {
        let mut out = String::new();
        let mut upper = false;
        for c in snake.chars() {
            if c == '_' {
                upper = true;
            } else if upper {
                out.push(c.to_ascii_uppercase());
                upper = false;
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The text between the `(` that `src` starts with and the `)` that closes it.
    fn parenthesised(src: &str) -> &str {
        assert!(src.starts_with('('));
        let mut depth = 0usize;
        for (i, c) in src.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &src[1..i];
                    }
                }
                _ => {}
            }
        }
        panic!("unclosed parameter list: {src:.60}");
    }

    /// `a: X, b?: { c: Y, d: Z }[]` -> `[("a", "X"), ("b", "{ c: Y, d: Z }[]")]`: split at the
    /// commas that are not inside brackets (or the angle brackets of a generic type), then at
    /// the first colon. A `?` after the name is dropped.
    fn params(list: &str) -> Vec<(String, String)> {
        let mut parts = Vec::new();
        let mut depth = 0i32;
        let mut current = String::new();
        let mut previous = ' ';
        for c in list.chars() {
            match c {
                '(' | '[' | '{' | '<' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                // Not the `>` of an arrow (`=>` or `->`).
                '>' if previous != '=' && previous != '-' => depth -= 1,
                _ => {}
            }
            if c == ',' && depth == 0 {
                parts.push(std::mem::take(&mut current));
            } else {
                current.push(c);
            }
            previous = c;
        }
        parts.push(current);
        parts
            .iter()
            .filter(|p| !p.trim().is_empty())
            .map(|p| {
                let (name, ty) = p.split_once(':').expect("a parameter has a type");
                (
                    name.trim().trim_end_matches('?').to_string(),
                    ty.trim().to_string(),
                )
            })
            .collect()
    }

    /// The methods of `interface Api { ... }`, in order, each with its parameter names.
    fn api_methods() -> Vec<(String, Vec<String>)> {
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
                let rest = &line[name.len()..];
                (!name.is_empty() && rest.starts_with('(')).then(|| {
                    let names = params(parenthesised(rest))
                        .into_iter()
                        .map(|(name, _)| name)
                        .collect();
                    (name, names)
                })
            })
            .collect()
    }

    /// Every `#[tauri::command]` function in this file, with the names of the arguments the
    /// UI supplies. What Tauri injects (the app handle, the window, managed state) is left out.
    fn command_arguments() -> Vec<(String, Vec<String>)> {
        const INJECTED: &[&str] = &["AppHandle", "State<", "WebviewWindow"];
        let src = include_str!("commands.rs");
        // Up to the handler macro: nothing after it declares a command.
        let src = &src[..src.find("macro_rules! commands").unwrap()];
        src.split("#[tauri::command]\n")
            .skip(1)
            .map(|after| {
                let after = after
                    .strip_prefix("pub async fn ")
                    .or_else(|| after.strip_prefix("pub fn "))
                    .expect("a command is a `pub fn` or a `pub async fn`");
                let open = after.find('(').unwrap();
                let names = params(parenthesised(&after[open..]))
                    .into_iter()
                    .filter(|(_, ty)| !INJECTED.iter().any(|i| ty.starts_with(i)))
                    .map(|(name, _)| name)
                    .collect();
                (after[..open].to_string(), names)
            })
            .collect()
    }

    #[test]
    fn commands_match_api_contract() {
        let api = api_methods();
        let methods: Vec<String> = api.iter().map(|(name, _)| name.clone()).collect();
        assert!(methods.len() >= 18, "parsed too few methods: {methods:?}");

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

        // Every command takes exactly the arguments its method declares, under the same names
        // (Tauri maps the UI's camelCase keys onto the snake_case Rust arguments).
        let declared = command_arguments();
        let declared_names: BTreeSet<String> = declared.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(
            declared_names, registered,
            "the `#[tauri::command]` functions differ from the registered list"
        );
        for (method, parameters) in api.iter().filter(|(m, _)| !m.starts_with("on")) {
            let (_, arguments) = declared
                .iter()
                .find(|(name, _)| *name == snake(method))
                .expect("checked above");
            let arguments: Vec<String> = arguments.iter().map(|a| camel(a)).collect();
            assert_eq!(
                &arguments,
                parameters,
                "the arguments of `{}` differ from the parameters of `Api.{method}`",
                snake(method)
            );
        }
    }

    #[test]
    fn parameter_lists_are_parsed_by_name() {
        let names = |list: &str| -> Vec<String> {
            params(list).into_iter().map(|(name, _)| name).collect()
        };
        assert_eq!(names(""), Vec::<String>::new());
        assert_eq!(names("ip?: string"), ["ip"]);
        assert_eq!(
            names("decisions: { tokenId: string; decision: Decision }[]"),
            ["decisions"]
        );
        assert_eq!(names("cb: (e: ProxyEvent, n: number) => void"), ["cb"]);
        assert_eq!(names("a: Map<string, number>, b: X"), ["a", "b"]);
        assert_eq!(
            params("\n    session: State<'_, Session>,\n    two_words: Option<String>,\n"),
            [
                ("session".to_string(), "State<'_, Session>".to_string()),
                ("two_words".to_string(), "Option<String>".to_string())
            ]
        );
        assert_eq!(
            parenthesised("(a: (b) => c): Promise<void>;"),
            "a: (b) => c"
        );
        assert_eq!(camel("two_words"), "twoWords");
        assert_eq!(camel("ip"), "ip");

        // The commands of this file, as the contract test sees them.
        let declared = command_arguments();
        let of = |name: &str| declared.iter().find(|(n, _)| n == name).unwrap().1.clone();
        assert_eq!(of("get_state"), Vec::<String>::new());
        assert_eq!(of("start_proxy"), ["ip"]);
        assert_eq!(of("bw_apply"), ["decisions"]);
        assert_eq!(of("export_file"), ["dest"]);
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
            releases_url: "https://example.com/releases".into(),
        };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"step":"welcome","device":"iphone","resumeCleanup":false,"version":"0.1.0","releasesUrl":"https://example.com/releases"}"#
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
