//! Authy backup: parse the two API responses, decrypt with the backup password, name tokens (package 1A).

use crate::totp::{clean_secret, decode_secret};
use crate::types::{
    CapturedBackup, EncryptedToken, InvalidReason, InvalidToken, NativeApp, Secret, Token, Unlocked,
};
use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use sha1::Sha1;
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    #[error("malformed response: {0}")]
    Malformed(String),
}

/// The one way [`unlock`] fails: the password does not open the backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("wrong backup password")]
pub struct WrongPassword;

/// Authy's fixed PBKDF2 round count before the response started carrying one per token.
const DEFAULT_KDF_ITERATIONS: u32 = 1000;
/// The most key-derivation rounds a token may ask for. Authy uses 100,000. The number comes
/// from the response, so without a limit a corrupted or hostile one could keep the unlock
/// busy for hours; a token that asks for more is treated as one that cannot be decrypted.
pub const MAX_KDF_ITERATIONS: u32 = 2_000_000;
/// Standard tokens are six digits unless the response says otherwise.
const DEFAULT_TOKEN_DIGITS: u32 = 6;
/// Authy-native tokens are seven digits unless the response says otherwise.
const DEFAULT_NATIVE_DIGITS: u32 = 7;

/// Every field is optional here so that one entry missing something is a decision for the
/// caller (fail the parse, or drop the entry), not a serde error that loses the whole body.
/// A field of the wrong type is still an error.
#[derive(Deserialize)]
struct RawToken {
    #[serde(default, deserialize_with = "string_or_number")]
    unique_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    original_name: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    logo: Option<String>,
    #[serde(default)]
    account_type: Option<String>,
    #[serde(default, deserialize_with = "lenient_u32")]
    digits: Option<u32>,
    #[serde(default)]
    encrypted_seed: Option<String>,
    #[serde(default)]
    salt: Option<String>,
    #[serde(default)]
    unique_iv: Option<String>,
    #[serde(default, deserialize_with = "lenient_u32")]
    key_derivation_iterations: Option<u32>,
}

impl RawToken {
    /// `None` when the entry lacks what is needed to use it.
    fn into_token(self) -> Option<EncryptedToken> {
        let unique_id = self.unique_id.filter(|s| !s.is_empty())?;
        let encrypted_seed = self.encrypted_seed.filter(|s| !s.is_empty())?;
        let salt = self.salt.filter(|s| !s.is_empty())?;
        let name = self
            .name
            .filter(|n| !n.is_empty())
            .or(self.original_name.filter(|n| !n.is_empty()))?;
        Some(EncryptedToken {
            unique_id,
            name,
            issuer: self.issuer,
            logo: self.logo,
            account_type: self.account_type.unwrap_or_default(),
            digits: self
                .digits
                .filter(|d| *d != 0)
                .unwrap_or(DEFAULT_TOKEN_DIGITS),
            encrypted_seed,
            salt,
            unique_iv: self.unique_iv.filter(|s| !s.is_empty()),
            key_derivation_iterations: self
                .key_derivation_iterations
                .filter(|n| *n != 0)
                .unwrap_or(DEFAULT_KDF_ITERATIONS),
        })
    }
}

#[derive(Deserialize)]
struct TokensEnvelope {
    authenticator_tokens: Vec<RawToken>,
}

/// Only the fields that are kept. `secret_seed` is deliberately absent, so serde skips it
/// without ever building a value for it.
#[derive(Deserialize)]
struct RawApp {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "lenient_u32")]
    digits: Option<u32>,
}

impl RawApp {
    fn into_app(self) -> Option<NativeApp> {
        Some(NativeApp {
            name: self.name.filter(|n| !n.is_empty())?,
            digits: self
                .digits
                .filter(|d| *d != 0)
                .unwrap_or(DEFAULT_NATIVE_DIGITS),
        })
    }
}

#[derive(Deserialize)]
struct AppsEnvelope {
    apps: Vec<RawApp>,
}

fn malformed(e: serde_json::Error) -> BackupError {
    // serde's message names fields and positions, never echoes values we care about.
    BackupError::Malformed(e.to_string())
}

fn unusable(what: &str) -> BackupError {
    BackupError::Malformed(format!("{what} entry is missing a required field"))
}

/// Parse `{"authenticator_tokens":[...]}`. An entry that cannot be used is an error.
pub fn parse_tokens_response(body: &[u8]) -> Result<Vec<EncryptedToken>, BackupError> {
    let env: TokensEnvelope = serde_json::from_slice(body).map_err(malformed)?;
    env.authenticator_tokens
        .into_iter()
        .map(|t| t.into_token().ok_or_else(|| unusable("token")))
        .collect()
}

/// Parse `{"apps":[...]}`. Only name and digits are read; the seed is never deserialized.
/// An entry that cannot be used is an error.
pub fn parse_apps_response(body: &[u8]) -> Result<Vec<NativeApp>, BackupError> {
    let env: AppsEnvelope = serde_json::from_slice(body).map_err(malformed)?;
    env.apps
        .into_iter()
        .map(|a| a.into_app().ok_or_else(|| unusable("app")))
        .collect()
}

/// Like [`parse_tokens_response`], but entries that cannot be used are dropped and the rest
/// kept. For the proxy, which sees whatever Authy sends and must not lose a whole backup to
/// one odd entry.
pub(crate) fn parse_tokens_response_lenient(
    body: &[u8],
) -> Result<Vec<EncryptedToken>, BackupError> {
    let env: TokensEnvelope = serde_json::from_slice(body).map_err(malformed)?;
    Ok(env
        .authenticator_tokens
        .into_iter()
        .filter_map(RawToken::into_token)
        .collect())
}

/// Like [`parse_apps_response`], dropping entries that cannot be used.
pub(crate) fn parse_apps_response_lenient(body: &[u8]) -> Result<Vec<NativeApp>, BackupError> {
    let env: AppsEnvelope = serde_json::from_slice(body).map_err(malformed)?;
    Ok(env.apps.into_iter().filter_map(RawApp::into_app).collect())
}

/// A JSON string, number or null, kept as a string.
fn string_or_number<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    struct V;
    impl Visitor<'_> for V {
        type Value = Option<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string, a number or null")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.to_owned()))
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }
    d.deserialize_any(V)
}

/// A JSON number, a string of digits, or null.
fn lenient_u32<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u32>, D::Error> {
    struct V;
    impl Visitor<'_> for V {
        type Value = Option<u32>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a non-negative integer, a string of digits or null")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            u32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            u32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.trim().parse().map(Some).map_err(E::custom)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }
    d.deserialize_any(V)
}

/// Decrypt one token's seed. `None` when padding is invalid or the plaintext is not printable ASCII.
fn decrypt_seed(tok: &EncryptedToken, password: &str) -> Option<String> {
    if tok.key_derivation_iterations == 0 || tok.key_derivation_iterations > MAX_KDF_ITERATIONS {
        return None;
    }
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(
        password.as_bytes(),
        tok.salt.as_bytes(),
        tok.key_derivation_iterations,
        &mut key,
    );
    let iv: [u8; 16] = match tok.unique_iv.as_deref() {
        None | Some("") => [0u8; 16],
        Some(h) => hex::decode(h).ok()?.try_into().ok()?,
    };
    let ct = STANDARD.decode(&tok.encrypted_seed).ok()?;
    let dec = cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv);
    key.zeroize();
    let mut plain = dec.ok()?.decrypt_padded_vec_mut::<Pkcs7>(&ct).ok()?;
    let ok = plain.iter().all(|b| (0x20..=0x7e).contains(b));
    let out = if ok {
        String::from_utf8(plain.clone()).ok()
    } else {
        None
    };
    plain.zeroize();
    out
}

fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_alpha = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_alpha {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_alpha = true;
        } else {
            out.push(c);
            prev_alpha = false;
        }
    }
    out
}

fn looks_like_email(s: &str) -> bool {
    !s.chars().any(char::is_whitespace)
        && s.split_once('@')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
}

/// Returns (issuer, username, title).
fn name_token(tok: &EncryptedToken) -> (Option<String>, Option<String>, String) {
    let name = tok.name.as_str();
    let username = if let Some((_, u)) = name.split_once(": ") {
        Some(u.to_string())
    } else if looks_like_email(name) {
        Some(name.to_string())
    } else {
        None
    };
    let mut issuer = tok.issuer.clone().filter(|s| !s.trim().is_empty());
    if issuer.is_none() {
        if let Some(logo) = tok.logo.as_deref() {
            let first = logo.split_whitespace().next().unwrap_or("");
            if !first.is_empty()
                && !logo.starts_with("authenticator")
                && !name.to_lowercase().contains(&first.to_lowercase())
            {
                issuer = Some(title_case(logo));
            }
        }
    }
    let title = match &issuer {
        Some(i) if !name.to_lowercase().contains(&i.to_lowercase()) => format!("{i} ({name})"),
        _ => name.to_string(),
    };
    (issuer, username, title)
}

/// Decrypt the backup with the password exactly as typed.
///
/// Tokens that fail to decrypt individually (when the password is right overall) are reported in
/// `invalid` as `NotBase32`, since the type has no other reason; they are never exported. The
/// same goes for a token whose number of digits no code can have. Every token that does come
/// out can therefore show a code.
pub fn unlock(backup: &CapturedBackup, password: &str) -> Result<Unlocked, WrongPassword> {
    let total = backup.tokens.len();
    let mut tokens = Vec::new();
    let mut invalid = Vec::new();
    let mut decrypted = 0usize;
    let mut failed = 0usize;
    for t in &backup.tokens {
        let Some(mut seed) = decrypt_seed(t, password) else {
            failed += 1;
            // Even if every remaining token decrypted, fewer than half would: stop early.
            if (total - failed) * 2 < total {
                return Err(WrongPassword);
            }
            invalid.push(InvalidToken {
                name: t.name.clone(),
                reason: InvalidReason::NotBase32,
            });
            continue;
        };
        decrypted += 1;
        let mut cleaned = clean_secret(&seed);
        seed.zeroize();
        match decode_secret(&cleaned) {
            Err(_) => invalid.push(InvalidToken {
                name: t.name.clone(),
                reason: InvalidReason::NotBase32,
            }),
            Ok(bytes) if bytes.len() < 10 => invalid.push(InvalidToken {
                name: t.name.clone(),
                reason: InvalidReason::TooShort,
            }),
            // No authenticator makes codes of this length ([`crate::totp::code`] refuses it),
            // so the token could never be checked. The type has no reason of its own for it.
            Ok(_) if !(1..=10).contains(&t.digits) => invalid.push(InvalidToken {
                name: t.name.clone(),
                reason: InvalidReason::NotBase32,
            }),
            Ok(_) => {
                let (issuer, username, title) = name_token(t);
                tokens.push(Token {
                    id: t.unique_id.clone(),
                    title,
                    name: t.name.clone(),
                    issuer,
                    username,
                    secret: Secret::new(cleaned.clone()),
                    digits: t.digits,
                    period: 30,
                });
            }
        }
        cleaned.zeroize();
    }
    if decrypted * 2 < total {
        return Err(WrongPassword);
    }
    Ok(Unlocked {
        tokens,
        invalid,
        native: backup.native_apps.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockEncryptMut;

    const ITER: u32 = 1000; // low for test speed; the algorithm is identical
    const PW: &str = "correct horse";
    const GOOD: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    fn encrypt(
        password: &str,
        salt: &str,
        iv: Option<[u8; 16]>,
        plain: &str,
    ) -> (String, Option<String>) {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), ITER, &mut key);
        let iv_bytes = iv.unwrap_or([0u8; 16]);
        let ct = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv_bytes)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes());
        (STANDARD.encode(ct), iv.map(hex::encode))
    }

    fn make(i: usize, name: &str, plain: &str, iv: bool, pw: &str) -> EncryptedToken {
        let salt = format!("salt-number-{i}");
        let ivb = iv.then(|| [i as u8 + 1; 16]);
        let (encrypted_seed, unique_iv) = encrypt(pw, &salt, ivb, plain);
        EncryptedToken {
            unique_id: i.to_string(),
            name: name.into(),
            issuer: None,
            logo: None,
            account_type: "authenticator".into(),
            digits: 6,
            encrypted_seed,
            salt,
            unique_iv,
            key_derivation_iterations: ITER,
        }
    }

    fn backup(tokens: Vec<EncryptedToken>) -> CapturedBackup {
        CapturedBackup {
            tokens,
            native_apps: vec![],
        }
    }

    fn twenty(pw: &str) -> CapturedBackup {
        backup(
            (0..20)
                .map(|i| make(i, &format!("Account {i}"), GOOD, i % 2 == 0, pw))
                .collect(),
        )
    }

    #[test]
    fn decrypts_with_iv() {
        let u = unlock(&backup(vec![make(1, "A", GOOD, true, PW)]), PW).unwrap();
        assert_eq!(u.tokens.len(), 1);
        assert_eq!(u.tokens[0].secret.expose(), GOOD);
        assert_eq!(u.tokens[0].period, 30);
    }

    #[test]
    fn a_token_no_code_can_be_made_for_is_listed_as_unusable_not_dropped_later() {
        // Authy says how many digits a token's codes have. A number no code can have must
        // not come out as a token: it would be exported, and then be missing, with no reason
        // given, from the list of codes to check.
        let mut odd = make(1, "Eleven Digits", GOOD, true, PW);
        odd.digits = 11;
        let fine = make(2, "Eight Digits", GOOD, true, PW);
        let u = unlock(&backup(vec![odd, EncryptedToken { digits: 8, ..fine }]), PW).unwrap();
        let titles: Vec<&str> = u.tokens.iter().map(|t| t.title.as_str()).collect();
        assert_eq!(titles, ["Eight Digits"]);
        assert_eq!(
            u.invalid,
            vec![InvalidToken {
                name: "Eleven Digits".into(),
                reason: InvalidReason::NotBase32
            }]
        );
        for token in &u.tokens {
            crate::totp::code(token.secret.expose(), token.digits, token.period, 59)
                .expect("every token that comes out can show a code");
        }
    }

    #[test]
    fn decrypts_with_zero_iv() {
        let t = make(1, "A", GOOD, false, PW);
        assert!(t.unique_iv.is_none());
        let u = unlock(&backup(vec![t]), PW).unwrap();
        assert_eq!(u.tokens[0].secret.expose(), GOOD);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let b = twenty(PW);
        assert_eq!(b.tokens.len(), 20);
        assert!(matches!(unlock(&b, "not the password"), Err(WrongPassword)));
        assert_eq!(unlock(&b, PW).unwrap().tokens.len(), 20);
    }

    #[test]
    fn password_is_used_verbatim() {
        for pw in [" pass ", "pässwörd"] {
            let b = backup(vec![
                make(1, "A", GOOD, true, pw),
                make(2, "B", GOOD, true, pw),
            ]);
            assert_eq!(unlock(&b, pw).unwrap().tokens.len(), 2);
            let mut wrongs = vec!["passwörd".to_string(), "password".into(), format!("{pw} ")];
            if pw.trim() != pw {
                wrongs.push(pw.trim().to_string());
            }
            for wrong in &wrongs {
                assert!(
                    matches!(unlock(&b, wrong), Err(WrongPassword)),
                    "{wrong:?} must not unlock"
                );
            }
        }
    }

    #[test]
    fn an_absurd_round_count_is_unusable_not_hours_of_work() {
        // A hostile or corrupted response can name any number of rounds. Two thousand
        // million would keep a processor busy for hours; it must be turned down at once.
        let mut absurd = make(0, "Absurd", "JBSWY3DPEHPK3PXP", true, "pw");
        absurd.key_derivation_iterations = u32::MAX;
        let mut over = make(1, "Just over", "JBSWY3DPEHPK3PXP", true, "pw");
        over.key_derivation_iterations = MAX_KDF_ITERATIONS + 1;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = unlock(&backup(vec![absurd, over]), "pw");
            let _ = tx.send(matches!(outcome, Err(WrongPassword)));
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("the round count was not capped: still deriving after three seconds");
        assert!(refused, "nothing in it could be decrypted");

        // The real count, and one well above it, still work; such a token among good ones
        // is reported, not fatal.
        let mut tokens: Vec<EncryptedToken> = (0..3)
            .map(|i| make(i, &format!("Good {i}"), "JBSWY3DPEHPK3PXP", true, "pw"))
            .collect();
        let mut bad = make(9, "Too many rounds", "JBSWY3DPEHPK3PXP", true, "pw");
        bad.key_derivation_iterations = u32::MAX;
        tokens.push(bad);
        let unlocked = unlock(&backup(tokens), "pw").unwrap();
        assert_eq!(unlocked.tokens.len(), 3);
        assert_eq!(unlocked.invalid.len(), 1);
        assert_eq!(unlocked.invalid[0].name, "Too many rounds");
        // Room above Authy's 100,000.
        const { assert!(MAX_KDF_ITERATIONS >= 20 * 100_000) };
    }

    #[test]
    fn non_base32_secret_is_invalid_not_fatal() {
        let b = backup(vec![
            make(1, "Good", GOOD, true, PW),
            make(2, "Bad", "ABC1DEF8G", true, PW),
            make(3, "Short", "JBSWY3DP", true, PW),
            make(4, "Spaced", "jbsw y3dp-ehpk 3pxp====", true, PW),
        ]);
        let u = unlock(&b, PW).unwrap();
        assert_eq!(
            u.invalid,
            vec![
                InvalidToken {
                    name: "Bad".into(),
                    reason: InvalidReason::NotBase32
                },
                InvalidToken {
                    name: "Short".into(),
                    reason: InvalidReason::TooShort
                },
            ]
        );
        let names: Vec<_> = u.tokens.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Good", "Spaced"]);
        assert_eq!(u.tokens[1].secret.expose(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn unique_id_accepts_number_or_string() {
        let body = br#"{"authenticator_tokens":[
          {"unique_id":12345,"name":"A","encrypted_seed":"AA==","salt":"s","key_derivation_iterations":1},
          {"unique_id":"abc","name":"B","issuer":null,"logo":null,"digits":7,"unique_iv":"",
           "encrypted_seed":"AA==","salt":"s","key_derivation_iterations":1}]}"#;
        let t = parse_tokens_response(body).unwrap();
        assert_eq!(t[0].unique_id, "12345");
        assert_eq!(t[0].digits, 6);
        assert_eq!(t[1].unique_id, "abc");
        assert_eq!(t[1].digits, 7);
        assert_eq!(t[1].unique_iv, None);
    }

    fn named(name: &str, issuer: Option<&str>, logo: Option<&str>) -> Token {
        let mut t = make(1, name, GOOD, true, PW);
        t.issuer = issuer.map(Into::into);
        t.logo = logo.map(Into::into);
        unlock(&backup(vec![t]), PW).unwrap().tokens.remove(0)
    }

    #[test]
    fn title_uses_logo_when_issuer_blank() {
        let t = named("jeff@example.com", Some(""), Some("vercel"));
        assert_eq!(t.issuer.as_deref(), Some("Vercel"));
        assert_eq!(t.title, "Vercel (jeff@example.com)");
        // multi-word and mixed-case logos are title-cased
        let t = named("me", None, Some("digital ocean"));
        assert_eq!(t.title, "Digital Ocean (me)");
        // generic logos are ignored
        let t = named("me", None, Some("authenticator_1"));
        assert_eq!(t.issuer, None);
        assert_eq!(t.title, "me");
    }

    #[test]
    fn title_is_not_doubled_when_name_has_issuer() {
        let t = named("GitHub: jeff", Some("GitHub"), None);
        assert_eq!(t.title, "GitHub: jeff");
        // logo already named in the account name: no issuer invented
        let t = named("Vercel: jeff", None, Some("vercel"));
        assert_eq!(t.issuer, None);
        assert_eq!(t.title, "Vercel: jeff");
        let t = named("jeff", Some("GitHub"), None);
        assert_eq!(t.title, "GitHub (jeff)");
    }

    #[test]
    fn username_from_colon_and_from_email() {
        assert_eq!(
            named("GitHub: jeff", None, None).username.as_deref(),
            Some("jeff")
        );
        assert_eq!(
            named("jeff@example.com", None, None).username.as_deref(),
            Some("jeff@example.com")
        );
        assert_eq!(named("Just a name", None, None).username, None);
        assert_eq!(
            named("a: b: c", None, None).username.as_deref(),
            Some("b: c")
        );
    }

    #[test]
    fn apps_response_lists_names_only() {
        let body =
            br#"{"apps":[{"name":"Authy Native","digits":7,"_id":"x","secret_seed":"DEADBEEF"}]}"#;
        let apps = parse_apps_response(body).unwrap();
        assert_eq!(
            apps,
            vec![NativeApp {
                name: "Authy Native".into(),
                digits: 7
            }]
        );
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        for body in [
            &b""[..],
            b"not json",
            b"{}",
            b"[]",
            b"null",
            br#"{"authenticator_tokens":[{"name":1}]}"#,
            br#"{"authenticator_tokens":"x"}"#,
            br#"{"apps":[{}]}"#,
            &[0xff, 0xfe, 0x00],
        ] {
            assert!(matches!(
                parse_tokens_response(body),
                Err(BackupError::Malformed(_))
            ));
            assert!(matches!(
                parse_apps_response(body),
                Err(BackupError::Malformed(_))
            ));
        }
    }

    #[test]
    fn unusable_entries_fail_the_strict_parse_and_are_dropped_by_the_lenient_one() {
        let body = br#"{"authenticator_tokens":[
            {"unique_id":1,"name":"no seed","salt":"s"},
            {"unique_id":2,"name":"ok","encrypted_seed":"AAAA","salt":"s","digits":0,"key_derivation_iterations":0},
            {"name":"no id","encrypted_seed":"AAAA","salt":"s"}]}"#;
        assert!(matches!(
            parse_tokens_response(body),
            Err(BackupError::Malformed(_))
        ));
        let t = parse_tokens_response_lenient(body).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].digits, t[0].key_derivation_iterations), (6, 1000));

        let apps = br#"{"apps":[{"digits":7},{"name":"Kept"}]}"#;
        assert!(parse_apps_response(apps).is_err());
        assert_eq!(parse_apps_response_lenient(apps).unwrap().len(), 1);
    }

    #[test]
    fn garbage_token_fields_do_not_panic() {
        let mut t = make(1, "A", GOOD, true, PW);
        t.unique_iv = Some("zz".into());
        let mut u = make(2, "B", GOOD, true, PW);
        u.encrypted_seed = "!!!".into();
        let mut v = make(3, "C", GOOD, true, PW);
        v.encrypted_seed = STANDARD.encode([1u8; 5]);
        assert!(matches!(
            unlock(&backup(vec![t, u, v]), PW),
            Err(WrongPassword)
        ));
    }
}
