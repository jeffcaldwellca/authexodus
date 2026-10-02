use authexodus_core::export::{export, otpauth_uri, qr_svg, Destination, ExportError};
use authexodus_core::types::{Secret, Token};
use serde_json::Value;
use std::path::PathBuf;

fn tok(
    name: &str,
    issuer: Option<&str>,
    username: Option<&str>,
    secret: &str,
    digits: u32,
) -> Token {
    Token {
        id: name.to_string(),
        title: name.to_string(),
        name: name.to_string(),
        issuer: issuer.map(str::to_string),
        username: username.map(str::to_string),
        secret: Secret::new(secret.to_string()),
        digits,
        period: 30,
    }
}

fn sample() -> Vec<Token> {
    vec![
        tok("Mason", Some("Deno"), None, "JBSWY3DPEHPK3PXP", 6),
        tok(
            "Vercel: jeff@example.com",
            Some("Vercel"),
            Some("jeff@example.com"),
            "GEZDGNBVGY3TQOJQ",
            8,
        ),
    ]
}

const HOSTILE: [&str; 6] = [
    "a,b",
    "say \"hi\"",
    "a+b: c&d=e/f",
    "emoji \u{1F512}\u{1F680} \u{00E9}",
    "line1\nline2",
    " lead and trail ",
];

fn hostile() -> Vec<Token> {
    HOSTILE
        .iter()
        .map(|n| tok(n, Some("Iss&uer+x"), None, "JBSWY3DPEHPK3PXP", 6))
        .collect()
}

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/export")
        .join(name);
    std::fs::read_to_string(p).unwrap()
}

fn text(f: &authexodus_core::export::ExportFile) -> String {
    String::from_utf8(f.bytes.clone()).unwrap()
}

/// Parse an otpauth URI back into (name, secret, issuer).
fn parse_uri(uri: &str) -> (String, String, Option<String>) {
    let u = url::Url::parse(uri).unwrap();
    assert_eq!(u.scheme(), "otpauth");
    assert_eq!(u.host_str(), Some("totp"));
    let name = percent_encoding::percent_decode_str(u.path().trim_start_matches('/'))
        .decode_utf8()
        .unwrap()
        .to_string();
    let mut secret = String::new();
    let mut issuer = None;
    for (k, v) in u.query_pairs() {
        match &*k {
            "secret" => secret = v.to_string(),
            "issuer" => issuer = Some(v.to_string()),
            _ => {}
        }
    }
    (name, secret, issuer)
}

/// Replace the random / clock-derived fields so output can be compared to a fixture.
fn normalise(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if k == "uuid" {
                    *val = Value::String("UUID".into());
                } else if k == "updatedAt" {
                    *val = Value::from(0);
                } else {
                    normalise(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(normalise),
        _ => {}
    }
}

fn json_of(f: &authexodus_core::export::ExportFile) -> Value {
    let mut v: Value = serde_json::from_slice(&f.bytes).unwrap();
    normalise(&mut v);
    v
}

#[test]
fn otpauth_uri_percent_encodes_label_and_issuer() {
    let t = tok(
        "Vercel: a+b@x.com",
        Some("My & Co"),
        None,
        "JBSWY3DPEHPK3PXP",
        6,
    );
    assert_eq!(
        otpauth_uri(&t),
        "otpauth://totp/Vercel%3A%20a%2Bb%40x.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20%26%20Co&digits=6&period=30"
    );
    let no_issuer = tok("x", None, None, "JBSWY3DPEHPK3PXP", 8);
    assert_eq!(
        otpauth_uri(&no_issuer),
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8&period=30"
    );
}

#[test]
fn qr_svg_renders_an_svg() {
    let svg = qr_svg("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
    assert!(svg.contains("<svg"));
}

#[test]
fn hostile_names_round_trip() {
    let tokens = hostile();

    // otpauth URIs
    for t in &tokens {
        let (name, secret, issuer) = parse_uri(&otpauth_uri(t));
        assert_eq!(name, t.name);
        assert_eq!(secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(issuer.as_deref(), Some("Iss&uer+x"));
    }

    // plain text: one line per token, each parses back
    let plain = text(&export(&tokens, Destination::PlainText).unwrap());
    let lines: Vec<&str> = plain.lines().collect();
    assert_eq!(lines.len(), tokens.len());
    for (line, t) in lines.iter().zip(&tokens) {
        assert_eq!(parse_uri(line).0, t.name);
    }

    // CSVs: title and the otpauth URI both come back
    for (dest, uri_col) in [(Destination::Bitwarden, 10), (Destination::OnePassword, 5)] {
        let f = export(&tokens, dest).unwrap();
        let mut rdr = csv::Reader::from_reader(f.bytes.as_slice());
        let rows: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), tokens.len());
        for (row, t) in rows.iter().zip(&tokens) {
            let title_col = if matches!(dest, Destination::Bitwarden) {
                3
            } else {
                0
            };
            assert_eq!(&row[title_col], t.title);
            let (name, secret, _) = parse_uri(&row[uri_col]);
            assert_eq!(name, t.name);
            assert_eq!(secret, "JBSWY3DPEHPK3PXP");
        }
    }

    // JSON formats
    for dest in [Destination::Aegis, Destination::ProtonAuthenticator] {
        let v = json_of(&export(&tokens, dest).unwrap());
        let entries = v["db"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), tokens.len());
        for (e, t) in entries.iter().zip(&tokens) {
            assert_eq!(e["name"], t.name.as_str());
            assert_eq!(e["info"]["secret"], "JBSWY3DPEHPK3PXP");
            assert_eq!(e["issuer"], "Iss&uer+x");
        }
    }
    let v = json_of(&export(&tokens, Destination::TwoFas).unwrap());
    let services = v["services"].as_array().unwrap();
    assert_eq!(services.len(), tokens.len());
    for (s, t) in services.iter().zip(&tokens) {
        assert_eq!(s["name"], t.title.as_str());
        assert_eq!(s["otp"]["account"], t.name.as_str());
        assert_eq!(s["secret"], "JBSWY3DPEHPK3PXP");
    }
}

#[test]
fn bitwarden_csv_matches_known_header_and_row() {
    let t = tok(
        "Mason",
        Some("Deno"),
        Some("mason@example.com"),
        "JBSWY3DPEHPK3PXP",
        6,
    );
    let f = export(&[t], Destination::Bitwarden).unwrap();
    assert_eq!(f.suggested_name, "authy-bitwarden-import.csv");
    let s = text(&f);
    let mut lines = s.split("\r\n");
    assert_eq!(
        lines.next().unwrap(),
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"
    );
    assert_eq!(
        lines.next().unwrap(),
        "Authy import,,login,Mason,Migrated from Authy,,,,mason@example.com,,otpauth://totp/Mason?secret=JBSWY3DPEHPK3PXP&issuer=Deno&digits=6&period=30"
    );
}

#[test]
fn onepassword_csv_matches_documented_sample() {
    let f = export(&sample(), Destination::OnePassword).unwrap();
    assert_eq!(text(&f), fixture("onepassword.csv"));
}

#[test]
fn aegis_matches_documented_sample() {
    let f = export(&sample(), Destination::Aegis).unwrap();
    let want: Value = serde_json::from_str(&fixture("aegis_plain.json")).unwrap();
    assert_eq!(json_of(&f), want);
    // uuids are real and distinct
    let raw: Value = serde_json::from_slice(&f.bytes).unwrap();
    let a = raw["db"]["entries"][0]["uuid"].as_str().unwrap();
    let b = raw["db"]["entries"][1]["uuid"].as_str().unwrap();
    assert_ne!(a, b);
    assert!(uuid::Uuid::parse_str(a).is_ok());
}

#[test]
fn twofas_matches_documented_sample() {
    let f = export(&sample(), Destination::TwoFas).unwrap();
    let want: Value = serde_json::from_str(&fixture("twofas.json")).unwrap();
    assert_eq!(json_of(&f), want);
    assert!(f.suggested_name.ends_with(".2fas"));
}

#[test]
fn proton_matches_documented_sample() {
    let f = export(&sample(), Destination::ProtonAuthenticator).unwrap();
    let want: Value = serde_json::from_str(&fixture("aegis_plain.json")).unwrap();
    assert_eq!(json_of(&f), want);
    assert!(f.suggested_name.contains("proton"));
}

#[test]
fn plain_text_is_one_uri_per_line() {
    let f = export(&sample(), Destination::PlainText).unwrap();
    let s = text(&f);
    assert_eq!(s.lines().count(), 2);
    assert!(s.starts_with("otpauth://totp/Mason?secret=JBSWY3DPEHPK3PXP&issuer=Deno"));
}

#[test]
fn google_has_no_file() {
    assert_eq!(
        export(&sample(), Destination::GoogleAuthenticator),
        Err(ExportError::NoFileForDestination)
    );
}

#[test]
fn empty_token_list_exports_valid_empty_file() {
    let none: [Token; 0] = [];
    let bw = export(&none, Destination::Bitwarden).unwrap();
    let mut r = csv::Reader::from_reader(bw.bytes.as_slice());
    assert_eq!(r.headers().unwrap().len(), 11);
    assert_eq!(r.records().count(), 0);

    let op = export(&none, Destination::OnePassword).unwrap();
    let mut r = csv::Reader::from_reader(op.bytes.as_slice());
    assert_eq!(r.headers().unwrap().len(), 6);
    assert_eq!(r.records().count(), 0);

    assert!(export(&none, Destination::PlainText)
        .unwrap()
        .bytes
        .is_empty());

    for dest in [Destination::Aegis, Destination::ProtonAuthenticator] {
        let v = json_of(&export(&none, dest).unwrap());
        assert_eq!(v["db"]["entries"].as_array().unwrap().len(), 0);
    }
    let v = json_of(&export(&none, Destination::TwoFas).unwrap());
    assert_eq!(v["services"].as_array().unwrap().len(), 0);

    assert!(authexodus_core::export::google_migration_qrs(&none).is_empty());
}
