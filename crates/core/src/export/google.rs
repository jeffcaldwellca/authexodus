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

fn params(t: &Token) -> Option<OtpParameters> {
    let secret = BASE32_NOPAD.decode(t.secret.expose().as_bytes()).ok()?;
    Some(OtpParameters {
        secret,
        name: account(t).to_string(),
        issuer: issuer(t).to_string(),
        algorithm: Algorithm::Sha1 as i32,
        // Google only knows 6 and 8 digits.
        digits: if t.digits == 8 {
            DigitCount::Eight as i32
        } else {
            DigitCount::Six as i32
        },
        otp_type: OtpType::Totp as i32,
        counter: 0,
    })
}

/// The `otpauth-migration://` URLs, 10 accounts each. Tokens whose secret is not valid base32
/// are skipped (the caller reports those separately).
pub fn migration_urls(tokens: &[Token]) -> Vec<String> {
    let all: Vec<OtpParameters> = tokens.iter().filter_map(params).collect();
    let chunks: Vec<&[OtpParameters]> = all.chunks(BATCH_SIZE).collect();
    let batch_id = (uuid::Uuid::new_v4().as_u128() & 0x7fff_ffff) as i32;
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let payload = MigrationPayload {
                otp_parameters: chunk.to_vec(),
                version: 1,
                batch_size: chunks.len() as i32,
                batch_index: i as i32,
                batch_id,
            };
            let b64 = base64::engine::general_purpose::STANDARD.encode(payload.encode_to_vec());
            let data =
                percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC);
            format!("otpauth-migration://offline?data={data}")
        })
        .collect()
}

/// SVGs of the migration QR codes, in scan order.
pub fn google_migration_qrs(tokens: &[Token]) -> Vec<String> {
    migration_urls(tokens).iter().map(|u| qr_svg(u)).collect()
}
