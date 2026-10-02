//! RFC 6238 TOTP code generation (package 1A).

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    /// The secret is not valid base32, or digits/period are out of range.
    #[error("secret is not valid base32 (or digits/period out of range)")]
    BadSecret,
}

/// Strip spaces, `=` and `-`, uppercase. Shared with `backup` so both agree on what a secret is.
pub(crate) fn clean_secret(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Decode a cleaned secret to bytes.
pub(crate) fn decode_secret(cleaned: &str) -> Result<Vec<u8>, TotpError> {
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| TotpError::BadSecret)
}

/// HMAC-SHA1 TOTP code, zero-padded to `digits` (1..=10). `period` must be non-zero.
pub fn code(
    secret_b32: &str,
    digits: u32,
    period: u32,
    unix_time: u64,
) -> Result<String, TotpError> {
    if !(1..=10).contains(&digits) || period == 0 {
        return Err(TotpError::BadSecret);
    }
    let key = decode_secret(&clean_secret(secret_b32))?;
    if key.is_empty() {
        return Err(TotpError::BadSecret);
    }
    let counter = unix_time / u64::from(period);
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|_| TotpError::BadSecret)?;
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = usize::from(h[19] & 0x0f);
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    let n = u64::from(bin) % 10u64.pow(digits);
    Ok(format!("{n:0width$}", width = digits as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B, SHA-1, secret "12345678901234567890".
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn totp_matches_rfc6238_vectors() {
        for (t, want) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code(SECRET, 8, 30, t).unwrap(), want, "t={t}");
        }
    }

    #[test]
    fn totp_six_digit_thirty_second() {
        assert_eq!(code(SECRET, 6, 30, 59).unwrap(), "287082");
        // lowercase, spaced, padded input is cleaned
        assert_eq!(
            code("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq====", 6, 30, 59).unwrap(),
            "287082"
        );
    }

    #[test]
    fn bad_input_is_an_error() {
        assert_eq!(code("not base32 1!", 6, 30, 0), Err(TotpError::BadSecret));
        assert_eq!(code(SECRET, 0, 30, 0), Err(TotpError::BadSecret));
        assert_eq!(code(SECRET, 6, 0, 0), Err(TotpError::BadSecret));
        assert_eq!(code("", 6, 30, 0), Err(TotpError::BadSecret));
    }
}
