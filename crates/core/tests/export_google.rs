use authexodus_core::export::google::{migration_urls, DigitCount, MigrationPayload, OtpType};
use authexodus_core::export::google_migration_qrs;
use authexodus_core::types::{Secret, Token};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use prost::Message;

fn tokens(n: usize) -> Vec<Token> {
    (0..n)
        .map(|i| Token {
            id: i.to_string(),
            title: format!("Svc {i}"),
            name: format!("acct {i}, \"q\" + &"),
            issuer: Some(format!("Issuer {i}")),
            username: None,
            // distinct made-up secret per token
            secret: Secret::new(BASE32_NOPAD.encode(format!("secret-bytes-{i:04}").as_bytes())),
            digits: if i % 2 == 0 { 6 } else { 8 },
            period: 30,
        })
        .collect()
}

fn decode(url: &str) -> MigrationPayload {
    let u = url::Url::parse(url).unwrap();
    assert_eq!(u.scheme(), "otpauth-migration");
    assert_eq!(u.host_str(), Some("offline"));
    let data = u.query_pairs().find(|(k, _)| k == "data").unwrap().1;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .unwrap();
    MigrationPayload::decode(raw.as_slice()).unwrap()
}

#[test]
fn google_migration_batches_of_ten() {
    let toks = tokens(23);
    let urls = migration_urls(&toks);
    assert_eq!(urls.len(), 3);
    assert_eq!(google_migration_qrs(&toks).len(), 3);
    assert!(google_migration_qrs(&toks)
        .iter()
        .all(|s| s.contains("<svg")));

    let payloads: Vec<MigrationPayload> = urls.iter().map(|u| decode(u)).collect();
    assert_eq!(
        payloads
            .iter()
            .map(|p| p.otp_parameters.len())
            .collect::<Vec<_>>(),
        vec![10, 10, 3]
    );
    let batch_id = payloads[0].batch_id;
    for (i, p) in payloads.iter().enumerate() {
        assert_eq!(p.version, 1);
        assert_eq!(p.batch_size, 3);
        assert_eq!(p.batch_index, i as i32);
        assert_eq!(p.batch_id, batch_id);
    }

    let all: Vec<_> = payloads
        .iter()
        .flat_map(|p| p.otp_parameters.iter())
        .collect();
    assert_eq!(all.len(), 23);
    for (p, t) in all.iter().zip(&toks) {
        assert_eq!(
            p.secret,
            BASE32_NOPAD.decode(t.secret.expose().as_bytes()).unwrap()
        );
        assert_eq!(p.name, t.name);
        assert_eq!(Some(p.issuer.as_str()), t.issuer.as_deref());
        assert_eq!(p.otp_type, OtpType::Totp as i32);
        let want = if t.digits == 8 {
            DigitCount::Eight
        } else {
            DigitCount::Six
        };
        assert_eq!(p.digits, want as i32);
    }
}

#[test]
fn exactly_ten_is_one_batch_and_none_is_none() {
    assert_eq!(migration_urls(&tokens(10)).len(), 1);
    assert_eq!(migration_urls(&tokens(11)).len(), 2);
    assert!(migration_urls(&[]).is_empty());
}
