//! Export writer: Aegis plain (unencrypted) vault JSON (package 1B).
//! Shape from https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md
//! (envelope version 1, empty header, db version 3). Also used for Proton Authenticator.

use super::{account, issuer};
use crate::types::Token;
use serde_json::{json, Value};

pub fn write(tokens: &[Token]) -> Vec<u8> {
    let entries: Vec<Value> = tokens
        .iter()
        .map(|t| {
            json!({
                "type": "totp",
                "uuid": uuid::Uuid::new_v4().to_string(),
                "name": account(t),
                "issuer": issuer(t),
                "note": "",
                "favorite": false,
                "icon": null,
                "icon_mime": null,
                "icon_hash": null,
                "info": {
                    "secret": t.secret.expose(),
                    "algo": "SHA1",
                    "digits": t.digits,
                    "period": t.period,
                },
                "groups": [],
            })
        })
        .collect();
    let doc = json!({
        "version": 1,
        "header": { "slots": null, "params": null },
        "db": { "version": 3, "entries": entries, "groups": [] },
    });
    serde_json::to_vec_pretty(&doc).expect("json value serialises")
}
