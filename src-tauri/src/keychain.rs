//! `KeyStore` on the macOS Keychain via `keyring` (package 2A).
//!
//! The only file that touches the real Keychain. Tests never construct a `KeychainStore`.
//!
//! The item is never read back (`KeyStore` has no operation for it) and never updated in
//! place: a new run deletes whatever is there and creates the item again
//! (`Authority::create_fresh`), so the item's access rules are always the ones this app's own
//! creation gives it, and all a later launch does with an item is delete it.

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
