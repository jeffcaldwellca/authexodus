//! Certificate authority and the `KeyStore` trait (package 1C).
//!
//! One root per run: P-256, valid seven days, optionally name-constrained: DNS names are
//! permitted only under `authy.com`, and every IP address is excluded. For a client that
//! enforces name constraints, a leaked key could then vouch for a server only under a name
//! inside `authy.com`. (Whether iOS enforces them on a user-installed root is checked on a real
//! device; the unconstrained root is the fallback.) The certificate and its
//! private key live in a [`KeyStore`] (the macOS Keychain in the app, memory in tests) until
//! cleanup calls [`Authority::destroy`].
//!
//! Nothing here is Mac-only, and nothing here logs.

use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

/// What the person sees in Settings on the iPhone or iPad, so it says what to do with it.
pub const COMMON_NAME: &str = "authexodus (remove after use)";
/// The only DNS subtree a constrained root may issue for.
pub const PERMITTED_SUBTREE: &str = "authy.com";

const VALID_FOR: Duration = Duration::days(7);
/// Certificates are back-dated a little so a device whose clock runs behind still accepts them.
const BACKDATE: Duration = Duration::hours(1);
/// A stored root with less than this left is replaced rather than reused.
const MIN_REMAINING: Duration = Duration::hours(1);

const BLOB_MAGIC: &[u8; 4] = b"AXCA";
const BLOB_VERSION: u8 = 1;
const FLAG_CONSTRAINED: u8 = 1;
/// magic, version, flags, not-after (i64 unix seconds), certificate length (u32).
const BLOB_HEADER_LEN: usize = 4 + 1 + 1 + 8 + 4;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// The key store could not be read or written. The message comes from the store.
    #[error("key store: {0}")]
    Store(String),
    /// A certificate or key could not be generated or loaded.
    #[error("certificate: {0}")]
    Certificate(String),
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        CaError::Certificate(e.to_string())
    }
}

/// Where the root's certificate and private key are kept between start and cleanup.
///
/// The blob is opaque to the store and contains the private key: a store must keep it somewhere
/// only this app can read (the app uses the macOS Keychain).
pub trait KeyStore: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError>;
    fn store(&self, blob: &[u8]) -> Result<(), CaError>;
    fn delete(&self) -> Result<(), CaError>;
}

/// A [`KeyStore`] that lives and dies with the process. For tests.
#[derive(Default)]
pub struct MemoryKeyStore(Mutex<Option<Zeroizing<Vec<u8>>>>);

impl MemoryKeyStore {
    pub fn new() -> MemoryKeyStore {
        MemoryKeyStore::default()
    }

    fn slot(&self) -> Result<std::sync::MutexGuard<'_, Option<Zeroizing<Vec<u8>>>>, CaError> {
        self.0
            .lock()
            .map_err(|_| CaError::Store("memory key store is poisoned".into()))
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError> {
        Ok(self.slot()?.as_ref().map(|blob| blob.to_vec()))
    }

    fn store(&self, blob: &[u8]) -> Result<(), CaError> {
        *self.slot()? = Some(Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self) -> Result<(), CaError> {
        *self.slot()? = None;
        Ok(())
    }
}

/// The root certificate and its signing key. Deliberately has no `Debug`.
pub struct Authority {
    cert_der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    not_after: OffsetDateTime,
}

impl Authority {
    /// Reuse the root in `store`, or create one and store it.
    ///
    /// The stored root is reused only when it is intact, has time left, and matches
    /// `constrained`; otherwise a new one replaces it. (A device that installed the old
    /// certificate then has to install the new one, which is what a changed `constrained`
    /// asks for anyway.)
    pub fn load_or_create(store: &dyn KeyStore, constrained: bool) -> Result<Authority, CaError> {
        if let Some(blob) = store.load()? {
            let blob = Zeroizing::new(blob);
            if let Some(existing) = Authority::from_blob(&blob, constrained) {
                return Ok(existing);
            }
        }
        let (authority, blob) = Authority::create(constrained)?;
        store.store(&blob)?;
        Ok(authority)
    }

    /// The root certificate, DER encoded: what the iPhone or iPad downloads and installs.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    /// Remove the root and its key from `store`. Leaf certificates already issued die with the
    /// process; nothing can be signed with this root again.
    pub fn destroy(store: &dyn KeyStore) -> Result<(), CaError> {
        store.delete()
    }

    fn create(constrained: bool) -> Result<(Authority, Zeroizing<Vec<u8>>), CaError> {
        // Whole seconds, so the expiry kept in the stored blob is exactly the certificate's.
        let now = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
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
            params.name_constraints = Some(NameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName(PERMITTED_SUBTREE.to_owned())],
                // A permitted dNSName subtree does not restrict names of other types
                // (RFC 5280 4.2.1.10), so IP-address names are excluded entirely.
                excluded_subtrees: vec![
                    GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([0; 4], 0)),
                    GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix([0; 16], 0)),
                ],
            });
        }

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert_der = params.self_signed(&key)?.der().to_vec();
        let key_der = Zeroizing::new(key.serialize_der());
        let blob = encode_blob(constrained, not_after, &cert_der, &key_der);

        let authority = Authority {
            cert_der,
            issuer: Issuer::new(params, key),
            not_after,
        };
        Ok((authority, blob))
    }

    /// `None` when the blob is damaged, expired (or nearly), or of the other kind.
    fn from_blob(blob: &[u8], constrained: bool) -> Option<Authority> {
        let stored = decode_blob(blob)?;
        if stored.constrained != constrained {
            return None;
        }
        if stored.not_after - OffsetDateTime::now_utc() < MIN_REMAINING {
            return None;
        }
        let key = KeyPair::try_from(stored.key_der).ok()?;
        let cert = CertificateDer::from(stored.cert_der);
        let issuer = Issuer::from_ca_cert_der(&cert, key).ok()?;
        Some(Authority {
            cert_der: stored.cert_der.to_vec(),
            issuer,
            not_after: stored.not_after,
        })
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

/// 16 random bytes with the top bit clear, so the DER integer is positive and 16 bytes long.
fn random_serial() -> SerialNumber {
    let mut bytes = *uuid::Uuid::new_v4().as_bytes();
    bytes[0] &= 0x7f;
    bytes[0] |= 0x40;
    SerialNumber::from_slice(&bytes)
}

struct StoredRoot<'a> {
    constrained: bool,
    not_after: OffsetDateTime,
    cert_der: &'a [u8],
    key_der: &'a [u8],
}

/// The stored blob: a small header, then the certificate (DER), then the key (PKCS#8 DER).
fn encode_blob(
    constrained: bool,
    not_after: OffsetDateTime,
    cert_der: &[u8],
    key_der: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(
        BLOB_HEADER_LEN + cert_der.len() + key_der.len(),
    ));
    blob.extend_from_slice(BLOB_MAGIC);
    blob.push(BLOB_VERSION);
    blob.push(if constrained { FLAG_CONSTRAINED } else { 0 });
    blob.extend_from_slice(&not_after.unix_timestamp().to_be_bytes());
    blob.extend_from_slice(&(cert_der.len() as u32).to_be_bytes());
    blob.extend_from_slice(cert_der);
    blob.extend_from_slice(key_der);
    blob
}

fn decode_blob(blob: &[u8]) -> Option<StoredRoot<'_>> {
    if blob.len() < BLOB_HEADER_LEN || &blob[..4] != BLOB_MAGIC || blob[4] != BLOB_VERSION {
        return None;
    }
    let constrained = blob[5] & FLAG_CONSTRAINED != 0;
    let not_after = i64::from_be_bytes(blob[6..14].try_into().ok()?);
    let not_after = OffsetDateTime::from_unix_timestamp(not_after).ok()?;
    let cert_len = u32::from_be_bytes(blob[14..18].try_into().ok()?) as usize;
    let rest = &blob[BLOB_HEADER_LEN..];
    if cert_len == 0 || cert_len >= rest.len() {
        return None;
    }
    let (cert_der, key_der) = rest.split_at(cert_len);
    Some(StoredRoot {
        constrained,
        not_after,
        cert_der,
        key_der,
    })
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
    fn key_store_is_object_safe() {
        let store = MemoryKeyStore::new();
        let as_object: &dyn KeyStore = &store;
        assert!(as_object.load().unwrap().is_none());
        let boxed: Box<dyn KeyStore> = Box::new(MemoryKeyStore::new());
        boxed.store(b"x").unwrap();
        assert_eq!(boxed.load().unwrap().as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn ca_round_trips_through_keystore() {
        let store = MemoryKeyStore::new();
        let first = Authority::load_or_create(&store, true).unwrap();
        let blob = store.load().unwrap().expect("the root was stored");
        assert!(
            blob.windows(first.cert_der.len())
                .any(|w| w == first.cert_der.as_slice()),
            "the blob holds the certificate"
        );

        let second = Authority::load_or_create(&store, true).unwrap();
        assert_eq!(
            second.cert_der(),
            first.cert_der(),
            "same root, not a new one"
        );
        assert_eq!(second.not_after, first.not_after);
        assert_eq!(
            store.load().unwrap().unwrap(),
            blob,
            "the store is untouched"
        );

        // The reloaded root still holds the same key: a leaf it signs verifies against the
        // certificate the first one produced.
        let ca = parse(&first.cert_der);
        let leaf = leaf_der(&second, "api.authy.com");
        parse(&leaf)
            .verify_signature(Some(ca.public_key()))
            .expect("leaf signed by the stored key");
    }

    #[test]
    fn destroy_removes_the_key() {
        let store = MemoryKeyStore::new();
        let first = Authority::load_or_create(&store, true).unwrap();
        assert!(store.load().unwrap().is_some());

        Authority::destroy(&store).unwrap();
        assert!(store.load().unwrap().is_none(), "nothing left in the store");
        Authority::destroy(&store).unwrap(); // destroying twice is fine

        let second = Authority::load_or_create(&store, true).unwrap();
        assert_ne!(second.cert_der(), first.cert_der(), "a new root, a new key");
        let old_ca = parse(&first.cert_der);
        let leaf = leaf_der(&second, "api.authy.com");
        assert!(parse(&leaf)
            .verify_signature(Some(old_ca.public_key()))
            .is_err());
    }

    #[test]
    fn constrained_ca_has_name_constraint() {
        let authority = Authority::load_or_create(&MemoryKeyStore::new(), true).unwrap();
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
        let authority = Authority::load_or_create(&MemoryKeyStore::new(), false).unwrap();
        let der = authority.cert_der();
        assert!(!parse(&der)
            .extensions()
            .iter()
            .any(|e| matches!(e.parsed_extension(), ParsedExtension::NameConstraints(_))));
    }

    #[test]
    fn ca_is_a_seven_day_p256_root_with_the_expected_name() {
        let authority = Authority::load_or_create(&MemoryKeyStore::new(), true).unwrap();
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
    fn changing_the_constraint_issues_a_new_root() {
        let store = MemoryKeyStore::new();
        let constrained = Authority::load_or_create(&store, true).unwrap();
        let unconstrained = Authority::load_or_create(&store, false).unwrap();
        assert_ne!(constrained.cert_der(), unconstrained.cert_der());
        // and the store now holds the new one
        let again = Authority::load_or_create(&store, false).unwrap();
        assert_eq!(again.cert_der(), unconstrained.cert_der());
    }

    #[test]
    fn a_damaged_or_expired_blob_is_replaced() {
        let store = MemoryKeyStore::new();
        for junk in [
            &b""[..],
            b"AXCA",
            b"garbage that is long enough to have a header",
        ] {
            store.store(junk).unwrap();
            let authority = Authority::load_or_create(&store, true).unwrap();
            assert_ne!(store.load().unwrap().unwrap(), junk);
            parse(&authority.cert_der);
        }

        // A truncated key is damage too.
        let good = store.load().unwrap().unwrap();
        store.store(&good[..good.len() - 20]).unwrap();
        let replaced = Authority::load_or_create(&store, true).unwrap();
        assert_ne!(store.load().unwrap().unwrap(), good);

        // An expired root (same certificate and key, header says it ended a minute ago).
        let current = store.load().unwrap().unwrap();
        let stored = decode_blob(&current).unwrap();
        let expired = encode_blob(
            true,
            OffsetDateTime::now_utc() - Duration::minutes(1),
            stored.cert_der,
            stored.key_der,
        );
        store.store(&expired).unwrap();
        let fresh = Authority::load_or_create(&store, true).unwrap();
        assert_ne!(fresh.cert_der(), replaced.cert_der());
    }

    #[test]
    fn leaf_is_for_the_host_and_signed_by_the_root() {
        let authority = Authority::load_or_create(&MemoryKeyStore::new(), true).unwrap();
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

    /// A store that fails, to show errors surface instead of being swallowed.
    struct BrokenStore;
    impl KeyStore for BrokenStore {
        fn load(&self) -> Result<Option<Vec<u8>>, CaError> {
            Err(CaError::Store("locked".into()))
        }
        fn store(&self, _: &[u8]) -> Result<(), CaError> {
            Err(CaError::Store("locked".into()))
        }
        fn delete(&self) -> Result<(), CaError> {
            Err(CaError::Store("locked".into()))
        }
    }

    #[test]
    fn key_store_failures_surface() {
        assert!(matches!(
            Authority::load_or_create(&BrokenStore, true),
            Err(CaError::Store(_))
        ));
        assert!(matches!(
            Authority::destroy(&BrokenStore),
            Err(CaError::Store(_))
        ));
    }
}
