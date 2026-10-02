//! Recognise Authy responses worth capturing; pure functions (package 1C).
//!
//! Two response bodies matter (shapes taken from `reference/manual-run-2026-10-02/capture.py`):
//!
//! * the encrypted backup, `{"authenticator_tokens":[{...}], ...}`;
//! * the Authy-native app list, `{"apps":[{name, digits, secret_seed, ...}], ...}`.
//!
//! Everything else is ignored. The native apps' `secret_seed` is never deserialised into
//! anything: the structs in `backup` name only the fields that are kept, and serde skips the
//! rest without building a value for them.
//!
//! The parsing itself lives in `backup` (the lenient variants of `parse_tokens_response` and
//! `parse_apps_response`); this module only decides which shape a body has.

use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::backup;
use crate::types::{CapturedBackup, EncryptedToken, NativeApp};

/// Something recognised in a response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Captured {
    Tokens(Vec<EncryptedToken>),
    NativeApps(Vec<NativeApp>),
}

/// Recognise a response body. `None` for anything that is not one of the two shapes above.
///
/// The body must already be decoded (no `Content-Encoding`). Entries that lack what is needed
/// to use them (a token without `encrypted_seed` or `salt`, an app without a name) are dropped
/// rather than failing the whole body.
pub fn inspect(body: &[u8]) -> Option<Captured> {
    // Which shape is it? `IgnoredAny` looks at a value without building one.
    let probe: Probe = serde_json::from_slice(body).ok()?;
    if probe.authenticator_tokens.is_some() {
        return backup::parse_tokens_response_lenient(body)
            .ok()
            .map(Captured::Tokens);
    }
    if probe.apps.is_some() {
        return backup::parse_apps_response_lenient(body)
            .ok()
            .map(Captured::NativeApps);
    }
    None
}

#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    authenticator_tokens: Option<IgnoredAny>,
    #[serde(default)]
    apps: Option<IgnoredAny>,
}

/// Fold a capture into the backup. Returns `true` if the backup grew.
///
/// Authy sends the backup more than once, and a later copy can be empty. Each half of the
/// backup is therefore replaced only by a strictly larger set: the largest capture wins and is
/// never clobbered by a smaller or empty one.
pub fn merge(into: &mut CapturedBackup, new: Captured) -> bool {
    match new {
        Captured::Tokens(tokens) if tokens.len() > into.tokens.len() => {
            into.tokens = tokens;
            true
        }
        Captured::NativeApps(apps) if apps.len() > into.native_apps.len() => {
            into.native_apps = apps;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic tokens body in the real response's shape. Nothing here is real data.
    fn tokens_body(n: usize) -> Vec<u8> {
        let tokens: Vec<serde_json::Value> = (0..n)
            .map(|i| {
                serde_json::json!({
                    "account_type": "authenticator",
                    "digits": 6,
                    "encrypted_seed": format!("c3ludGhldGljLXNlZWQt{i}"),
                    "issuer": if i % 2 == 0 { serde_json::json!("Example") } else { serde_json::Value::Null },
                    "key_derivation_iterations": 100000,
                    "logo": serde_json::Value::Null,
                    "name": format!("Example: user{i}@example.com"),
                    "original_name": format!("Example: user{i}@example.com"),
                    "password_timestamp": 1700000000,
                    "salt": format!("salt{i}"),
                    // the real response gives a number for some tokens and a string for others
                    "unique_id": if i % 2 == 0 { serde_json::json!(1000 + i) } else { serde_json::json!((1000 + i).to_string()) },
                    "unique_iv": if i % 3 == 0 { serde_json::Value::Null } else { serde_json::json!("000102030405060708090a0b0c0d0e0f") },
                })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "message": "success",
            "authenticator_tokens": tokens,
            "deleted": [],
            "success": true,
        }))
        .unwrap()
    }

    fn tokens(n: usize) -> Captured {
        inspect(&tokens_body(n)).expect("a tokens body")
    }

    const APPS_BODY: &str = r#"{"message":"success","apps":[
        {"name":"Twitch","digits":7,"secret_seed":"00112233445566778899aabbccddeeff","_id":"1"},
        {"name":"Example Native","digits":"7","secret_seed":"ffeeddccbbaa99887766554433221100"}
    ],"deleted":[],"success":true}"#;

    #[test]
    fn inspect_recognises_a_tokens_body() {
        let Some(Captured::Tokens(tokens)) = inspect(&tokens_body(3)) else {
            panic!("expected tokens");
        };
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].unique_id, "1000"); // JSON number
        assert_eq!(tokens[1].unique_id, "1001"); // JSON string
        assert_eq!(tokens[0].name, "Example: user0@example.com");
        assert_eq!(tokens[0].issuer.as_deref(), Some("Example"));
        assert_eq!(tokens[1].issuer, None);
        assert_eq!(tokens[0].logo, None);
        assert_eq!(tokens[0].account_type, "authenticator");
        assert_eq!(tokens[0].digits, 6);
        assert_eq!(tokens[0].encrypted_seed, "c3ludGhldGljLXNlZWQt0");
        assert_eq!(tokens[0].salt, "salt0");
        assert_eq!(tokens[0].unique_iv, None);
        assert_eq!(
            tokens[1].unique_iv.as_deref(),
            Some("000102030405060708090a0b0c0d0e0f")
        );
        assert_eq!(tokens[0].key_derivation_iterations, 100000);
    }

    #[test]
    fn inspect_recognises_an_apps_body() {
        let Some(Captured::NativeApps(apps)) = inspect(APPS_BODY.as_bytes()) else {
            panic!("expected apps");
        };
        assert_eq!(
            apps,
            vec![
                NativeApp {
                    name: "Twitch".into(),
                    digits: 7
                },
                NativeApp {
                    name: "Example Native".into(),
                    digits: 7
                },
            ]
        );
    }

    #[test]
    fn inspect_never_keeps_the_native_seed() {
        let captured = inspect(APPS_BODY.as_bytes()).unwrap();
        let printed = format!("{captured:?}");
        assert!(!printed.contains("00112233445566778899aabbccddeeff"));
        assert!(!printed.contains("secret_seed"));
    }

    #[test]
    fn inspect_ignores_anything_else() {
        let ignored: &[&[u8]] = &[
            b"",
            b"not json",
            b"<html><body>hello</body></html>",
            b"[]",
            b"null",
            b"42",
            br#"{"success":true,"message":"ok"}"#,
            br#"{"authenticator_tokens":"nope"}"#,
            br#"{"authenticator_tokens":null,"apps":null}"#,
            br#"{"apps":{"a":1}}"#,
            br#"{"devices":[{"name":"iPad"}]}"#,
            br#"{"authenticator_tokens":[1,2,3]}"#,
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00", // still gzip-encoded
        ];
        for body in ignored {
            assert_eq!(inspect(body), None, "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn inspect_accepts_an_empty_token_list() {
        assert_eq!(
            inspect(br#"{"authenticator_tokens":[]}"#),
            Some(Captured::Tokens(vec![]))
        );
    }

    #[test]
    fn inspect_drops_unusable_entries_and_keeps_the_rest() {
        let body = br#"{"authenticator_tokens":[
            {"name":"no seed","salt":"s","unique_id":1},
            {"name":"ok","encrypted_seed":"AAAA","salt":"s","unique_id":2},
            {"original_name":"renamed","encrypted_seed":"BBBB","salt":"t","unique_id":"3","digits":"8"}
        ]}"#;
        let Some(Captured::Tokens(tokens)) = inspect(body) else {
            panic!("expected tokens");
        };
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].name, "ok");
        assert_eq!(tokens[0].digits, 6);
        assert_eq!(tokens[0].key_derivation_iterations, 1000);
        assert_eq!(tokens[1].name, "renamed");
        assert_eq!(tokens[1].digits, 8);

        let apps = inspect(br#"{"apps":[{"digits":7},{"name":"Kept"}]}"#);
        assert_eq!(
            apps,
            Some(Captured::NativeApps(vec![NativeApp {
                name: "Kept".into(),
                digits: 7
            }]))
        );
    }

    #[test]
    fn later_empty_response_does_not_clobber() {
        let mut backup = CapturedBackup::default();
        assert!(merge(&mut backup, tokens(40)));
        assert_eq!(backup.tokens.len(), 40);

        let empty = inspect(br#"{"authenticator_tokens":[]}"#).unwrap();
        assert!(!merge(&mut backup, empty));
        assert_eq!(backup.tokens.len(), 40);
    }

    #[test]
    fn merge_keeps_the_larger_set() {
        let mut backup = CapturedBackup::default();
        assert!(merge(&mut backup, tokens(5)));
        assert!(!merge(&mut backup, tokens(3)), "smaller never replaces");
        assert_eq!(backup.tokens.len(), 5);
        assert!(!merge(&mut backup, tokens(5)), "same size is not growth");
        assert!(merge(&mut backup, tokens(8)), "larger replaces");
        assert_eq!(backup.tokens.len(), 8);
        assert_eq!(backup.tokens[7].unique_id, "1007");
    }

    #[test]
    fn merge_tracks_tokens_and_native_apps_independently() {
        let mut backup = CapturedBackup::default();
        assert!(merge(&mut backup, tokens(4)));
        assert!(merge(
            &mut backup,
            inspect(APPS_BODY.as_bytes()).expect("apps")
        ));
        assert_eq!(backup.tokens.len(), 4);
        assert_eq!(backup.native_apps.len(), 2);

        assert!(!merge(&mut backup, Captured::NativeApps(vec![])));
        assert!(!merge(&mut backup, Captured::Tokens(vec![])));
        assert_eq!(backup.tokens.len(), 4);
        assert_eq!(backup.native_apps.len(), 2);
    }

    #[test]
    fn merging_nothing_into_an_empty_backup_is_not_growth() {
        let mut backup = CapturedBackup::default();
        assert!(!merge(&mut backup, Captured::Tokens(vec![])));
        assert_eq!(backup, CapturedBackup::default());
    }
}
