//! `KeyStore` on the macOS Keychain via `keyring` (package 2A).
//!
//! The only file that touches the real Keychain. Tests never construct a `KeychainStore`.
//!
//! The session never reads the item back to use it and never updates it in place: a new run
//! deletes whatever is there and creates the item again (`Authority::create_fresh`), so the
//! item's access rules are always the ones this app's own creation gives it.

use authexodus_core::ca::{CaError, KeyStore};

/// The name the item goes by in Keychain Access: what the person searches for if the app
/// cannot delete it.
pub const KEYCHAIN_SERVICE: &str = "dev.somecorp.authexodus";
const ACCOUNT: &str = "ca";

pub struct KeychainStore;

impl KeychainStore {
    fn entry() -> Result<keyring::Entry, CaError> {
        keyring::Entry::new(KEYCHAIN_SERVICE, ACCOUNT).map_err(|e| CaError::Store(e.to_string()))
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
