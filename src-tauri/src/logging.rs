//! The app's log: where it goes, how much of it there is, and what may be in it.
//!
//! The log goes to standard error and nowhere else. It is never written to a file, so nothing
//! about a run outlives the Terminal window it was started from; started from the Finder, the
//! app's standard error goes nowhere. To see it, start the app from Terminal:
//!
//! ```text
//! /Applications/authexodus.app/Contents/MacOS/authexodus
//! AUTHEXODUS_LOG=debug /Applications/authexodus.app/Contents/MacOS/authexodus
//! ```
//!
//! Only this app's own two crates are heard. Every other library is switched off whatever the
//! level, and the `log` crate (which rustls writes to) is not connected at all: a library's
//! own messages could name the sites the iPhone or iPad visits.
//!
//! What the app's own lines may hold is set where they are written (`authexodus_core::proxy`
//! and `crate::session`): stages, kinds, counts, status codes, request paths of the two
//! intercepted hosts with ids removed, this computer's address and the accepted device's. No
//! query string, no body, no other host, no password, key, code, name or file path.

use authexodus_core::bitwarden::BwError;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

/// Set to `debug` (or `trace`, `warn`, `error`) to change how much is logged. Default `info`.
pub const LOG_ENV: &str = "AUTHEXODUS_LOG";
/// The crates whose log lines are heard (matched as the start of a line's module path).
pub const OWN_CRATES: &[&str] = &["authexodus_core", "authexodus_lib", "authexodus"];

/// The level for a value of [`LOG_ENV`]: `info` unless it names another one.
pub fn log_level(value: Option<&str>) -> Level {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("trace") => Level::TRACE,
        Some("debug") => Level::DEBUG,
        Some("warn") | Some("warning") => Level::WARN,
        Some("error") => Level::ERROR,
        _ => Level::INFO,
    }
}

/// A subscriber that writes this app's own lines, at `level` and above, to `writer`.
pub fn subscriber<W>(level: Level, writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let own = OWN_CRATES.iter().fold(Targets::new(), |targets, name| {
        targets.with_target(*name, level)
    });
    tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(own),
    )
}

/// Send the log to standard error for the rest of the process. Called once, at start.
pub fn init() {
    let level = log_level(std::env::var(LOG_ENV).ok().as_deref());
    // Not `.init()`: that would also connect the `log` crate, and with it rustls.
    if tracing::subscriber::set_global_default(subscriber(level, std::io::stderr)).is_ok() {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            level = %level,
            "authexodus started; the log goes to standard error only and is never written to a file"
        );
    }
}

/// The kind of a Bitwarden failure, for the log.
pub fn bw_error_kind(error: &BwError) -> &'static str {
    match error {
        BwError::Server(_) => "server",
        BwError::SessionExpired => "sessionExpired",
        BwError::Cli(_) => "cli",
        BwError::Download(_) => "download",
        BwError::ChecksumMismatch => "checksumMismatch",
        BwError::Input(_) => "input",
        BwError::Unsupported(_) => "unsupported",
    }
}

/// A message from the Bitwarden tool made fit for the log. The tool's text can carry what the
/// person typed or what a server chose to say, so: one line, at most 200 characters, and every
/// word that holds an `@` (an email address), a `://` (an address), a `/` or `\` (a path), or
/// is long enough to be a key or an id (20 characters or more, or 6 or more digits) becomes
/// `[removed]`. Quoted text, which is how the tool repeats names back, is removed whole.
pub fn sanitised(message: &str) -> String {
    const LIMIT: usize = 200;
    let mut out = String::new();
    let mut in_quotes = false;
    for word in message.split_whitespace() {
        let quotes = word.matches(['"', '`']).count();
        let removed = in_quotes
            || quotes > 0
            || word.contains('@')
            || word.contains("://")
            || word.contains('/')
            || word.contains('\\')
            || word.chars().count() >= 20
            || word.chars().filter(char::is_ascii_digit).count() >= 6;
        if quotes % 2 == 1 {
            in_quotes = !in_quotes;
        }
        let word = if removed { "[removed]" } else { word };
        // Runs of removed words collapse into one mark.
        if removed && out.ends_with("[removed]") {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if out.chars().count() > LIMIT {
        out = out.chars().take(LIMIT).collect::<String>() + "...";
    }
    out
}

/// Let the process hold more open files than the 256 a Mac app starts with: every proxied
/// connection is two sockets, and a busy iPhone or iPad opens dozens at once. Returns the
/// limit now in force, or `None` if it could not be read.
#[cfg(unix)]
pub fn raise_open_file_limit() -> Option<u64> {
    const WANTED: libc::rlim_t = 4096;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    if limit.rlim_cur < WANTED {
        let raised = libc::rlimit {
            rlim_cur: WANTED.min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        // SAFETY: `raised` is a valid `rlimit`; the call only reads it.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            limit = raised;
        }
    }
    // `rlim_t` is `u64` on a Mac, but not on every Unix.
    #[allow(clippy::unnecessary_cast)]
    Some(limit.rlim_cur as u64)
}

#[cfg(not(unix))]
pub fn raise_open_file_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_level_is_info_unless_the_environment_names_another() {
        assert_eq!(log_level(None), Level::INFO);
        assert_eq!(log_level(Some("")), Level::INFO);
        assert_eq!(log_level(Some("nonsense")), Level::INFO);
        assert_eq!(log_level(Some("debug")), Level::DEBUG);
        assert_eq!(log_level(Some(" DEBUG ")), Level::DEBUG);
        assert_eq!(log_level(Some("trace")), Level::TRACE);
        assert_eq!(log_level(Some("warn")), Level::WARN);
        assert_eq!(log_level(Some("error")), Level::ERROR);
    }

    #[test]
    fn a_message_from_the_tool_is_stripped_of_what_could_identify_someone() {
        assert_eq!(sanitised("Vault is locked."), "Vault is locked.");
        assert_eq!(
            sanitised("Bitwarden CLI error: Item \"Chequing at Example Bank\" not found."),
            "Bitwarden CLI error: Item [removed] not found."
        );
        assert_eq!(
            sanitised(
                "Username sam@example.test could not log in to https://vault.example.test/api"
            ),
            "Username [removed] could not log in to [removed]"
        );
        assert_eq!(
            sanitised("two\nlines\tand   spaces"),
            "two lines and spaces"
        );
        assert_eq!(
            sanitised("session 4Nk9aVeryLongSessionKeyValue0000== refused, id 123456 /Users/sam/x"),
            "session [removed] refused, id [removed]"
        );
        let long = sanitised(&"word ".repeat(100));
        assert_eq!(long.chars().count(), 203);
        assert!(long.ends_with("..."));
        assert_eq!(sanitised(""), "");
    }

    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Buffer;
        fn make_writer(&'a self) -> Buffer {
            self.clone()
        }
    }

    #[test]
    fn only_the_apps_own_crates_are_heard_and_only_from_the_level_up() {
        let buffer = Buffer::default();
        let heard = || String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        tracing::subscriber::with_default(subscriber(Level::INFO, buffer.clone()), || {
            tracing::info!(target: "authexodus_core::proxy", "from the core");
            tracing::warn!(target: "authexodus_lib::session", "from the shell");
            tracing::debug!(target: "authexodus_core::proxy", "too quiet to be heard");
            // What a library might say about the device's traffic, at any level.
            tracing::error!(target: "hyper::proto", "connecting to planted-host.invalid");
            tracing::warn!(target: "rustls::conn", "alert for planted-host.invalid");
            tracing::info!(target: "reqwest::connect", "planted-host.invalid");
        });
        let text = heard();
        assert!(text.contains("from the core"), "{text}");
        assert!(text.contains("from the shell"), "{text}");
        assert!(!text.contains("too quiet"), "{text}");
        assert!(!text.contains("planted-host"), "{text}");
        assert!(!text.contains('\u{1b}'), "no colour codes: {text}");

        tracing::subscriber::with_default(subscriber(Level::DEBUG, buffer.clone()), || {
            tracing::debug!(target: "authexodus_core::proxy", "heard at debug");
            tracing::trace!(target: "hyper::proto", "planted-host.invalid again");
        });
        let text = heard();
        assert!(text.contains("heard at debug"), "{text}");
        assert!(!text.contains("planted-host"), "{text}");
    }

    #[test]
    fn every_bitwarden_error_has_a_kind() {
        assert_eq!(bw_error_kind(&BwError::SessionExpired), "sessionExpired");
        assert_eq!(bw_error_kind(&BwError::Cli("x".into())), "cli");
        assert_eq!(
            bw_error_kind(&BwError::Unsupported("x".into())),
            "unsupported"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_open_file_limit_is_high_enough_for_a_busy_device() {
        let limit = raise_open_file_limit().expect("the limit can be read");
        assert!(limit >= 1024, "{limit}");
    }
}
