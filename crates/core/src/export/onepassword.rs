//! Export writer: 1Password CSV (package 1B).
//!
//! 1Password's CSV import maps columns to fields; its support article says the column holding
//! the otpauth URLs must be labelled "one-time password" (see the fixture's `.source.txt`).

use super::otpauth_uri;
use crate::types::Token;

pub const HEADER: [&str; 6] = [
    "Title",
    "URL",
    "Username",
    "Password",
    "Notes",
    "one-time password",
];

pub fn write(tokens: &[Token]) -> Vec<u8> {
    let mut w = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(Vec::new());
    w.write_record(HEADER).expect("csv header to Vec");
    for t in tokens {
        w.write_record([
            t.title.as_str(),
            "",
            t.username.as_deref().unwrap_or(""),
            "",
            "Migrated from Authy",
            &otpauth_uri(t),
        ])
        .expect("csv row to Vec");
    }
    w.into_inner().expect("csv flush to Vec")
}
