//! Google Authenticator "Transfer accounts" payloads (package 1B).
//!
//! Google Authenticator has no file import; it scans QR codes holding an
//! `otpauth-migration://offline?data=<base64 protobuf>` URL. Up to 10 accounts go in each QR.

use super::{account, issuer, qr_svg};
use crate::types::Token;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    pub otp_parameters: Vec<OtpParameters>,
    #[prost(int32, tag = "2")]
    pub version: i32,
    #[prost(int32, tag = "3")]
    pub batch_size: i32,
    #[prost(int32, tag = "4")]
    pub batch_index: i32,
    #[prost(int32, tag = "5")]
    pub batch_id: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct OtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    pub secret: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub issuer: String,
    #[prost(enumeration = "Algorithm", tag = "4")]
    pub algorithm: i32,
    #[prost(enumeration = "DigitCount", tag = "5")]
    pub digits: i32,
    #[prost(enumeration = "OtpType", tag = "6")]
    pub otp_type: i32,
    #[prost(int64, tag = "7")]
    pub counter: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Algorithm {
    Unspecified = 0,
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
    Md5 = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum DigitCount {
    Unspecified = 0,
    Six = 1,
    Eight = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum OtpType {
    Unspecified = 0,
    Hotp = 1,
    Totp = 2,
}

pub const BATCH_SIZE: usize = 10;

/// Longest URL one QR code can carry at the error-correction level `qr_svg` uses (version 40-M,
/// 2331 bytes in byte mode).
const MAX_URL_LEN: usize = 2331;

/// Google only knows 6 and 8 digits; anything else would produce wrong codes, so it is excluded
/// rather than mapped. Tokens with a secret that is not base32 are excluded too.
fn params(t: &Token) -> Option<OtpParameters> {
    let digits = match t.digits {
        6 => DigitCount::Six,
        8 => DigitCount::Eight,
        _ => return None,
    };
    let secret = BASE32_NOPAD.decode(t.secret.expose().as_bytes()).ok()?;
    Some(OtpParameters {
        secret,
        name: account(t).to_string(),
        issuer: issuer(t).to_string(),
        algorithm: Algorithm::Sha1 as i32,
        digits: digits as i32,
        otp_type: OtpType::Totp as i32,
        counter: 0,
    })
}

fn url_for(chunk: &[OtpParameters], size: usize, index: usize, batch_id: i32) -> String {
    let payload = MigrationPayload {
        otp_parameters: chunk.to_vec(),
        version: 1,
        batch_size: size as i32,
        batch_index: index as i32,
        batch_id,
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload.encode_to_vec());
    let data = percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC);
    format!("otpauth-migration://offline?data={data}")
}

/// Would this group still fit one QR code? (Sized with the largest header values.)
fn fits(chunk: &[OtpParameters]) -> bool {
    url_for(chunk, 99, 99, i32::MAX).len() <= MAX_URL_LEN
}

/// Titles of the tokens the migration QR codes cannot carry: digits other than 6 or 8, a secret
/// that is not base32, or an entry too large for a QR code on its own.
pub fn google_unsupported(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| !params(t).is_some_and(|p| fits(&[p])))
        .map(|t| t.title.clone())
        .collect()
}

/// The `otpauth-migration://` URLs: at most 10 accounts each, fewer when a full group would not
/// fit one QR code. Tokens listed by [`google_unsupported`] are left out.
pub fn migration_urls(tokens: &[Token]) -> Vec<String> {
    let mut groups: Vec<Vec<OtpParameters>> = Vec::new();
    for p in tokens.iter().filter_map(params) {
        if !fits(std::slice::from_ref(&p)) {
            continue;
        }
        let joins_last = groups.last().is_some_and(|g| {
            g.len() < BATCH_SIZE && {
                let mut trial = g.clone();
                trial.push(p.clone());
                fits(&trial)
            }
        });
        if joins_last {
            groups.last_mut().expect("checked").push(p);
        } else {
            groups.push(vec![p]);
        }
    }
    let batch_id = (uuid::Uuid::new_v4().as_u128() & 0x7fff_ffff) as i32;
    groups
        .iter()
        .enumerate()
        .map(|(i, g)| url_for(g, groups.len(), i, batch_id))
        .collect()
}

/// SVGs of the migration QR codes, in scan order.
pub fn google_migration_qrs(tokens: &[Token]) -> Vec<String> {
    migration_urls(tokens).iter().map(|u| qr_svg(u)).collect()
}
