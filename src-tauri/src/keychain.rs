//! `KeyStore` on the macOS Keychain via `keyring` (package 2A).
//!
//! The only file that touches the real Keychain. Tests never construct a `KeychainStore`.

use authexodus_core::ca::{CaError, KeyStore};

const SERVICE: &str = "dev.somecorp.authexodus";
const ACCOUNT: &str = "ca";

pub struct KeychainStore;

impl KeychainStore {
    fn entry() -> Result<keyring::Entry, CaError> {
        keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| CaError::Store(e.to_string()))
    }
}

impl KeyStore for KeychainStore {
    fn load(&self) -> Result<Option<Vec<u8>>, CaError> {
        match Self::entry()?.get_secret() {
            Ok(blob) => Ok(Some(blob)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CaError::Store(e.to_string())),
        }
    }

    fn store(&self, blob: &[u8]) -> Result<(), CaError> {
        Self::entry()?
            .set_secret(blob)
            .map_err(|e| CaError::Store(e.to_string()))
    }

    /// Deleting what is not there succeeds: cleanup must be safe to run twice.
    fn delete(&self) -> Result<(), CaError> {
        match Self::entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CaError::Store(e.to_string())),
        }
    }
}
