//! Export writer: plain text, one otpauth URI per line (package 1B).

use super::otpauth_uri;
use crate::types::Token;

pub fn write(tokens: &[Token]) -> Vec<u8> {
    let mut out = String::new();
    for t in tokens {
        out.push_str(&otpauth_uri(t));
        out.push('\n');
    }
    out.into_bytes()
}
