//! Shared data types. FROZEN in Batch 0: changing a field here breaks every package.
//!
//! `Secret` deliberately has no `Debug` and no `Serialize`, and zeroizes on drop. Anything that
//! holds one (`Token`, `Unlocked`) therefore cannot be printed or serialized by accident.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One token as Authy returns it, still encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedToken {
    pub unique_id: String, // JSON gives a number or a string; store as string
    pub name: String,
    pub issuer: Option<String>,
    pub logo: Option<String>,
    pub account_type: String,
    pub digits: u32,
    pub encrypted_seed: String, // base64
    pub salt: String,
    pub unique_iv: Option<String>, // hex; None means a zero IV
    pub key_derivation_iterations: u32,
}

/// An Authy-native app (7-digit tokens): listed by name, never exported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeApp {
    pub name: String,
    pub digits: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedBackup {
    pub tokens: Vec<EncryptedToken>,
    pub native_apps: Vec<NativeApp>,
}

/// A base32 TOTP secret (uppercase, unpadded). Zeroized on drop; no `Debug`, no `Serialize`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(base32: String) -> Secret {
        Secret(base32)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub struct Token {
    pub id: String,             // = unique_id
    pub title: String,          // display name, e.g. "Vercel (jeff@example.com)"
    pub name: String,           // Authy's own name
    pub issuer: Option<String>, // issuer, or derived from logo when blank
    pub username: Option<String>,
    pub secret: Secret,
    pub digits: u32,
    pub period: u32, // always 30 for standard tokens
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidReason {
    NotBase32,
    TooShort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidToken {
    pub name: String,
    pub reason: InvalidReason,
}

#[derive(Clone)]
pub struct Unlocked {
    pub tokens: Vec<Token>,
    pub invalid: Vec<InvalidToken>,
    pub native: Vec<NativeApp>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    // Compile-time proof that `Secret` has neither `Debug` nor `Serialize`: if either were
    // implemented, `<Secret as Ambiguous<_>>::check()` would have two candidates and fail
    // to infer. (The classic "ambiguous if implemented" trick.)
    trait AmbiguousIfDebug<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
    impl<T: ?Sized + Debug> AmbiguousIfDebug<u8> for T {}

    trait AmbiguousIfSerialize<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
    impl<T: ?Sized + Serialize> AmbiguousIfSerialize<u8> for T {}

    #[test]
    fn secret_has_no_debug_and_no_serialize() {
        <Secret as AmbiguousIfDebug<_>>::check();
        <Secret as AmbiguousIfSerialize<_>>::check();
    }

    #[test]
    fn secret_exposes_what_it_was_given() {
        assert_eq!(
            Secret::new("JBSWY3DPEHPK3PXP".into()).expose(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn secret_zeroizes_in_place() {
        let mut s = Secret::new("JBSWY3DPEHPK3PXP".into());
        s.zeroize();
        assert_eq!(s.expose(), "");
    }
}
