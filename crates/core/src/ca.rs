//! Certificate authority (package 1C).
//!
//! One root per run: P-256, valid seven days, optionally name-constrained: DNS names are
//! permitted only under `authy.com`, and every IP address is excluded. For a client that
//! enforces name constraints, a leaked key could then vouch for a server only under a name
//! inside `authy.com`. (Whether iOS enforces them on a user-installed root is checked on a real
//! device; the unconstrained root is the fallback.)
//!
//! The root's private key exists only in this process's memory, inside the [`Authority`]: it
//! is never serialised, written to disk or handed to a key store. Dropping the `Authority`
//! wipes rcgen's copy of the key (see [`RootKey`]) and frees the signing key itself. Once the
//! process is gone, so is the key, and a certificate still installed on a device can never
//! vouch for anything again.
//!
//! Nothing here is Mac-only, and nothing here logs.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PublicKeyData, SanType, SerialNumber, SignatureAlgorithm, SigningKey,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// What the person sees in Settings on the iPhone or iPad, so it says what to do with it.
pub const COMMON_NAME: &str = "authexodus (remove after use)";
/// The only DNS subtree a constrained root may issue for.
pub const PERMITTED_SUBTREE: &str = "authy.com";

const VALID_FOR: Duration = Duration::days(7);
/// Certificates are back-dated a little so a device whose clock runs behind still accepts them.
const BACKDATE: Duration = Duration::hours(1);

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// A certificate or key could not be generated or loaded.
    #[error("certificate: {0}")]
    Certificate(String),
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        CaError::Certificate(e.to_string())
    }
}

/// The root's key pair. rcgen keeps a PKCS#8 copy of the private key beside the signing key;
/// that copy is wiped when this is dropped. The signing key itself belongs to aws-lc-rs, which
/// frees it on drop and offers no way to wipe it sooner.
pub(crate) struct RootKey(KeyPair);

impl RootKey {
    fn generate() -> Result<RootKey, CaError> {
        Ok(RootKey(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?))
    }
}

impl Zeroize for RootKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RootKey {}

impl PublicKeyData for RootKey {
    fn der_bytes(&self) -> &[u8] {
        self.0.der_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.0.algorithm()
    }
}

impl SigningKey for RootKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.0.sign(msg)
    }
}

/// The root certificate and its signing key, for one run. Deliberately has no `Debug` and no
/// way to get the private key out.
pub struct Authority {
    cert_der: Vec<u8>,
    issuer: Issuer<'static, RootKey>,
    not_after: OffsetDateTime,
    constrained: bool,
}

impl Authority {
    /// Create a root for a new run. The key is made here and stays in memory until the
    /// `Authority` is dropped.
    pub fn create(constrained: bool) -> Result<Authority, CaError> {
        let now = OffsetDateTime::now_utc();
        let not_after = now + VALID_FOR;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, COMMON_NAME);
        params.not_before = now - BACKDATE;
        params.not_after = not_after;
        params.serial_number = Some(random_serial());
        // A root that can sign leaves only, never another CA.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        if constrained {
            params.name_constraints = Some(name_constraints());
        }

        let key = RootKey::generate()?;
        let cert_der = params.self_signed(&key)?.der().to_vec();
        Ok(Authority {
            cert_der,
            issuer: Issuer::new(params, key),
            not_after,
            constrained,
        })
    }

    /// The root certificate, DER encoded: what the iPhone or iPad downloads and installs.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    /// Whether the root carries the name constraint (it can vouch only for names under
    /// [`PERMITTED_SUBTREE`]).
    pub fn is_constrained(&self) -> bool {
        self.constrained
    }

    /// The SHA-256 fingerprint of the certificate as an iPhone or iPad shows it under More
    /// Details: 32 upper-case hexadecimal pairs joined by colons.
    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.cert_der)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// A TLS server configuration presenting a fresh leaf for `host`, signed by this root.
    /// The device is offered HTTP/1.1 only.
    pub(crate) fn leaf_server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let (leaf, key) = self.issue_leaf(host)?;
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| CaError::Certificate(e.to_string()))?
                .with_no_client_auth()
                .with_single_cert(vec![leaf], key_der)
                .map_err(|e| CaError::Certificate(e.to_string()))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// A leaf for `host` with its own P-256 key: a DNS subject alternative name, the
    /// server-auth extended key usage, expiring with the root.
    fn issue_leaf(&self, host: &str) -> Result<(CertificateDer<'static>, KeyPair), CaError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(host.try_into()?)];
        params.not_before = OffsetDateTime::now_utc() - BACKDATE;
        params.not_after = self.not_after;
        params.serial_number = Some(random_serial());
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let leaf = params.signed_by(&key, &self.issuer)?;
        Ok((leaf.der().clone(), key))
    }
}

/// What a constrained root is limited to: DNS names under [`PERMITTED_SUBTREE`], and no IP
/// address at all.
fn name_constraints() -> NameConstraints {
    NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(PERMITTED_SUBTREE.to_owned())],
        // A permitted dNSName subtree does not restrict names of other types
        // (RFC 5280 4.2.1.10), so IP-address names are excluded entirely.
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([0; 4], 0)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix([0; 16], 0)),
        ],
    }
}

/// 16 random bytes with the top bit clear, so the DER integer is positive and 16 bytes long.
fn random_serial() -> SerialNumber {
    let mut bytes = *uuid::Uuid::new_v4().as_bytes();
    bytes[0] &= 0x7f;
    bytes[0] |= 0x40;
    SerialNumber::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        let (rest, cert) = X509Certificate::from_der(der).expect("valid DER");
        assert!(rest.is_empty());
        cert
    }

    fn leaf_der(authority: &Authority, host: &str) -> Vec<u8> {
        authority.issue_leaf(host).expect("leaf").0.to_vec()
    }

    #[test]
    fn the_root_signs_leaves_and_two_roots_share_nothing() {
        let first = Authority::create(true).unwrap();
        let ca = parse(&first.cert_der);
        let leaf = leaf_der(&first, "api.authy.com");
        parse(&leaf)
            .verify_signature(Some(ca.public_key()))
            .expect("leaf signed by the root's key");

        let second = Authority::create(true).unwrap();
        assert_ne!(second.cert_der(), first.cert_der(), "a new root, a new key");
        let leaf = leaf_der(&second, "api.authy.com");
        assert!(parse(&leaf)
            .verify_signature(Some(ca.public_key()))
            .is_err());
    }

    #[test]
    fn the_root_key_is_wiped_when_it_is_dropped() {
        // Checked by the compiler: the key is wiped when it is dropped.
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<RootKey>();

        let mut key = RootKey::generate().unwrap();
        assert!(!key.0.serialize_der().is_empty());
        let public = key.der_bytes().to_vec();
        key.zeroize();
        assert!(
            key.0.serialize_der().is_empty(),
            "the copy of the private key rcgen keeps is gone"
        );
        assert_eq!(key.der_bytes(), public, "the public half is not secret");
    }

    #[test]
    fn constrained_ca_has_name_constraint() {
        let authority = Authority::create(true).unwrap();
        let der = authority.cert_der();
        let cert = parse(&der);

        let ext = cert
            .extensions()
            .iter()
            .find(|e| matches!(e.parsed_extension(), ParsedExtension::NameConstraints(_)))
            .expect("a name constraints extension");
        assert!(ext.critical, "RFC 5280: name constraints must be critical");
        let ParsedExtension::NameConstraints(nc) = ext.parsed_extension() else {
            unreachable!()
        };
        let permitted = nc.permitted_subtrees.as_ref().expect("permitted subtrees");
        assert_eq!(permitted.len(), 1, "exactly one permitted subtree");
        assert!(
            matches!(permitted[0].base, GeneralName::DNSName("authy.com")),
            "{:?}",
            permitted[0].base
        );
        // A dNSName constraint says nothing about IP-address names, so every IP address is
        // excluded outright: 0.0.0.0/0 and ::/0 (address then mask, RFC 5280 4.2.1.10).
        let excluded = nc.excluded_subtrees.as_ref().expect("excluded subtrees");
        let excluded: Vec<&[u8]> = excluded
            .iter()
            .map(|subtree| match &subtree.base {
                GeneralName::IPAddress(bytes) => *bytes,
                other => panic!("unexpected excluded subtree {other:?}"),
            })
            .collect();
        assert_eq!(excluded, [&[0u8; 8][..], &[0u8; 32][..]]);
    }

    #[test]
    fn unconstrained_ca_has_no_name_constraint() {
        let authority = Authority::create(false).unwrap();
        let der = authority.cert_der();
        assert!(!parse(&der)
            .extensions()
            .iter()
            .any(|e| matches!(e.parsed_extension(), ParsedExtension::NameConstraints(_))));
    }

    #[test]
    fn ca_is_a_seven_day_p256_root_with_the_expected_name() {
        let authority = Authority::create(true).unwrap();
        let der = authority.cert_der();
        let cert = parse(&der);

        let cn: Vec<_> = cert
            .subject()
            .iter_common_name()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert_eq!(cn, ["authexodus (remove after use)"]);
        assert_eq!(cert.subject(), cert.issuer(), "self-signed");
        cert.verify_signature(None).expect("self-signature");

        // id-ecPublicKey with the prime256v1 curve
        let spki = cert.public_key();
        assert_eq!(spki.algorithm.algorithm.to_id_string(), "1.2.840.10045.2.1");
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .unwrap()
            .as_oid()
            .unwrap();
        assert_eq!(curve.to_id_string(), "1.2.840.10045.3.1.7");

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        assert!(not_before <= now, "already valid");
        assert!(
            (not_after - (now + 7 * 24 * 3600)).abs() < 120,
            "expires seven days from now"
        );

        let bc = cert
            .basic_constraints()
            .unwrap()
            .expect("basic constraints");
        assert!(bc.critical);
        assert!(bc.value.ca);
        assert_eq!(bc.value.path_len_constraint, Some(0));
        let ku = cert.key_usage().unwrap().expect("key usage");
        assert!(ku.value.key_cert_sign());
    }

    #[test]
    fn fingerprint_is_sha256_in_upper_case_pairs_joined_by_colons() {
        let authority = Authority::create(true).unwrap();
        let fingerprint = authority.fingerprint();
        let pairs: Vec<&str> = fingerprint.split(':').collect();
        assert_eq!(pairs.len(), 32, "{fingerprint}");
        assert_eq!(fingerprint.len(), 32 * 2 + 31);
        for pair in &pairs {
            assert_eq!(pair.len(), 2, "{fingerprint}");
            assert!(
                pair.bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
                "{fingerprint}"
            );
        }
        // It is the SHA-256 of the DER the device downloads.
        let digest = Sha256::digest(authority.cert_der());
        let bytes: Vec<u8> = pairs
            .iter()
            .map(|pair| u8::from_str_radix(pair, 16).unwrap())
            .collect();
        assert_eq!(bytes, digest.as_slice());
        // Another root, another fingerprint.
        let other = Authority::create(true).unwrap();
        assert_ne!(other.fingerprint(), fingerprint);

        assert!(authority.is_constrained());
        let open = Authority::create(false).unwrap();
        assert!(!open.is_constrained());
    }

    #[test]
    fn leaf_is_for_the_host_and_signed_by_the_root() {
        let authority = Authority::create(true).unwrap();
        let ca_der = authority.cert_der();
        let ca = parse(&ca_der);
        let der = leaf_der(&authority, "api.authy.com");
        let leaf = parse(&der);

        leaf.verify_signature(Some(ca.public_key()))
            .expect("signed by the root");
        assert_eq!(leaf.issuer(), ca.subject());
        let san = leaf
            .subject_alternative_name()
            .unwrap()
            .expect("subject alternative name");
        assert_eq!(san.value.general_names.len(), 1);
        assert!(matches!(
            san.value.general_names[0],
            GeneralName::DNSName("api.authy.com")
        ));
        let eku = leaf
            .extended_key_usage()
            .unwrap()
            .expect("extended key usage");
        assert!(eku.value.server_auth);
        assert!(!leaf.is_ca());
        assert!(
            leaf.validity().not_after.timestamp() <= ca.validity().not_after.timestamp(),
            "a leaf never outlives its root"
        );

        // Two leaves for one host differ (fresh key, fresh serial).
        assert_ne!(leaf_der(&authority, "api.authy.com"), der);

        let config = authority.leaf_server_config("api.authy.com").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
