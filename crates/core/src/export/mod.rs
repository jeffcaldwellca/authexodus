//! otpauth URIs, QR SVGs and `Destination` dispatch (package 1B).
//!
//! One writer per destination app lives in a sibling module. Every writer takes the same
//! `&[Token]` and returns bytes; none of them logs or prints a secret.

use crate::types::Token;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use qrcode::render::svg;
use qrcode::QrCode;

pub mod aegis;
pub mod bitwarden;
pub mod google;
pub mod onepassword;
pub mod plain;
pub mod twofas;

pub use google::{google_migration_qrs, google_unsupported};

/// Everything except RFC 3986 unreserved characters is percent-encoded, so a name with
/// `,` `"` `+` `:` `&` `/` emoji or a newline survives inside an otpauth label or query value.
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, ENCODE).to_string()
}

/// `otpauth://totp/{label}?secret=..&issuer=..&digits=..&period=..`
///
/// The label is Authy's own token name, as in the manual run that was imported into a real
/// vault. The issuer is omitted when there is none.
pub fn otpauth_uri(t: &Token) -> String {
    let mut uri = format!(
        "otpauth://totp/{}?secret={}",
        enc(&t.name),
        t.secret.expose()
    );
    if let Some(issuer) = t.issuer.as_deref().filter(|i| !i.is_empty()) {
        uri.push_str("&issuer=");
        uri.push_str(&enc(issuer));
    }
    uri.push_str(&format!("&digits={}&period={}", t.digits, t.period));
    uri
}

/// Render `data` as a QR code in SVG. Returns an empty string if `data` is too long for any QR
/// version (callers feed it single otpauth URIs or migration chunks, which always fit).
pub fn qr_svg(data: &str) -> String {
    match QrCode::new(data.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(256, 256)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Bitwarden,
    OnePassword,
    TwoFas,
    Aegis,
    GoogleAuthenticator,
    ProtonAuthenticator,
    PlainText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportFile {
    pub suggested_name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExportError {
    #[error("this destination has no import file; use its QR codes instead")]
    NoFileForDestination,
}

/// The account part shown by authenticator apps: the username when Authy gave one, else the
/// token's own name.
pub(crate) fn account(t: &Token) -> &str {
    t.username
        .as_deref()
        .filter(|u| !u.is_empty())
        .unwrap_or(&t.name)
}

pub(crate) fn issuer(t: &Token) -> &str {
    t.issuer.as_deref().unwrap_or("")
}

pub fn export(tokens: &[Token], dest: Destination) -> Result<ExportFile, ExportError> {
    let (name, bytes) = match dest {
        Destination::Bitwarden => ("authy-bitwarden-import.csv", bitwarden::write(tokens)),
        Destination::OnePassword => ("authy-1password-import.csv", onepassword::write(tokens)),
        Destination::TwoFas => ("authy-2fas-backup.2fas", twofas::write(tokens)),
        Destination::Aegis => ("authy-aegis-import.json", aegis::write(tokens)),
        // Proton Authenticator imports Aegis JSON, so it gets the Aegis shape under its own name.
        Destination::ProtonAuthenticator => (
            "authy-proton-authenticator-import.json",
            aegis::write(tokens),
        ),
        Destination::PlainText => ("authy-otpauth-uris.txt", plain::write(tokens)),
        Destination::GoogleAuthenticator => return Err(ExportError::NoFileForDestination),
    };
    Ok(ExportFile {
        suggested_name: name.to_string(),
        bytes,
    })
}
