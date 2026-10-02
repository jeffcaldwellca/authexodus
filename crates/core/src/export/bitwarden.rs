//! Export writer: Bitwarden CSV (package 1B). Shape proven by an import on 2026-10-02
//! (see `reference/manual-run-2026-10-02/to_bitwarden.py`).

use super::otpauth_uri;
use crate::types::Token;

pub const HEADER: [&str; 11] = [
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
];

pub fn write(tokens: &[Token]) -> Vec<u8> {
    let mut w = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(Vec::new());
    // Writing to a Vec cannot fail.
    w.write_record(HEADER).expect("csv header to Vec");
    for t in tokens {
        w.write_record([
            "Authy import",
            "",
            "login",
            &t.title,
            "Migrated from Authy",
            "",
            "",
            "",
            t.username.as_deref().unwrap_or(""),
            "",
            &otpauth_uri(t),
        ])
        .expect("csv row to Vec");
    }
    w.into_inner().expect("csv flush to Vec")
}
