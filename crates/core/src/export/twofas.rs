//! Export writer: 2FAS unencrypted backup JSON (package 1B).
//!
//! 2FAS publishes no schema page that could be fetched; the shape below follows samples of
//! real exports (see the fixture's `.source.txt`). Unverified against the app itself.

use super::{account, issuer};
use crate::types::Token;
use serde_json::{json, Value};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn write(tokens: &[Token]) -> Vec<u8> {
    let now = now_ms();
    let services: Vec<Value> = tokens
        .iter()
        .enumerate()
        .map(|(i, t)| {
            json!({
                "name": t.title,
                "secret": t.secret.expose(),
                "updatedAt": now,
                "otp": {
                    "label": account(t),
                    "account": account(t),
                    "issuer": issuer(t),
                    "digits": t.digits,
                    "period": t.period,
                    "algorithm": "SHA1",
                    "tokenType": "TOTP",
                    "source": "Manual",
                },
                "order": { "position": i },
            })
        })
        .collect();
    let doc = json!({
        "services": services,
        "groups": [],
        "updatedAt": now,
        "schemaVersion": 4,
        "appVersionName": "authexodus",
    });
    serde_json::to_vec_pretty(&doc).expect("json value serialises")
}
