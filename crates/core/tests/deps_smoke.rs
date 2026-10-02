//! Batch 0: proves the dependency set declared in Cargo.toml actually fits together, so the
//! parallel packages can rely on it. Not a behavioural test; safe to delete once Batch 1 lands.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type Enc = cbc::Encryptor<aes::Aes256>;
type Dec = cbc::Decryptor<aes::Aes256>;

#[test]
fn pbkdf2_aes_cbc_round_trip() {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 1000, &mut key);
    let iv = [0u8; 16];
    let ct = Enc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(b"JBSWY3DPEHPK3PXP");
    let pt = Dec::new(&key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .unwrap();
    assert_eq!(pt, b"JBSWY3DPEHPK3PXP");
}

#[test]
fn hmac_sha1_and_encodings() {
    let mut m = Hmac::<Sha1>::new_from_slice(b"12345678901234567890").unwrap();
    m.update(&1u64.to_be_bytes());
    assert_eq!(m.finalize().into_bytes().len(), 20);
    assert_eq!(data_encoding::BASE32_NOPAD.encode(b"hi"), "NBUQ");
    assert_eq!(hex::encode([0xab]), "ab");
}

#[test]
fn qr_svg_prost_csv_zip_compile() {
    let svg = qrcode::QrCode::new(b"otpauth://totp/x")
        .unwrap()
        .render::<qrcode::render::svg::Color>()
        .build();
    assert!(svg.contains("<svg"));

    #[derive(Clone, PartialEq, prost::Message)]
    struct Msg {
        #[prost(string, tag = "1")]
        name: String,
    }
    use prost::Message;
    assert_eq!(
        Msg::decode(Msg { name: "a".into() }.encode_to_vec().as_slice())
            .unwrap()
            .name,
        "a"
    );

    let mut w = csv::Writer::from_writer(vec![]);
    w.write_record(["a,b", "c\"d"]).unwrap();
    assert!(String::from_utf8(w.into_inner().unwrap())
        .unwrap()
        .starts_with("\"a,b\""));

    let _ = zip::ZipArchive::new(std::io::Cursor::new(Vec::<u8>::new())).err();
}
