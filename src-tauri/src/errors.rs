//! Every way a command can be refused, in one place.
//!
//! A refused command rejects with one string of the form `"<code>: <sentence>"`. The code is
//! for the screen's logic (which panel, which button); the sentence is for the person and is
//! shown exactly as written here. So:
//!
//! * the codes are the variants of [`ErrorCode`], and nothing else is ever sent as one;
//! * every sentence is written out in [`Reject`], in plain words, and is fixed text: nothing
//!   is put into one when it is used, so none can carry a file path, a server name, an id,
//!   or anything a person typed. What went wrong in detail goes to the log (see
//!   `crate::logging`), never into the sentence.

use authexodus_core::bitwarden::BwError;
use serde::Serialize;

/// What the screen may branch on. The names are part of the contract with the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorCode {
    AddressChanged,
    AddressNotPrivate,
    NoPrivateAddress,
    ListenFailed,
    KeychainFailed,
    CaptureWouldBeLost,
    BadEmail,
    BadServerUrl,
    BwDownloadFailed,
    BwChecksumMismatch,
    BwUnreachable,
    BwSessionExpired,
    BwVaultReadFailed,
    BwFailed,
    NotUnlocked,
    NoBackup,
    ExportFailed,
    CleanupKeychainFailed,
    CleanupFailed,
    Internal,
}

impl ErrorCode {
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::AddressChanged,
        ErrorCode::AddressNotPrivate,
        ErrorCode::NoPrivateAddress,
        ErrorCode::ListenFailed,
        ErrorCode::KeychainFailed,
        ErrorCode::CaptureWouldBeLost,
        ErrorCode::BadEmail,
        ErrorCode::BadServerUrl,
        ErrorCode::BwDownloadFailed,
        ErrorCode::BwChecksumMismatch,
        ErrorCode::BwUnreachable,
        ErrorCode::BwSessionExpired,
        ErrorCode::BwVaultReadFailed,
        ErrorCode::BwFailed,
        ErrorCode::NotUnlocked,
        ErrorCode::NoBackup,
        ErrorCode::ExportFailed,
        ErrorCode::CleanupKeychainFailed,
        ErrorCode::CleanupFailed,
        ErrorCode::Internal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::AddressChanged => "address_changed",
            ErrorCode::AddressNotPrivate => "address_not_private",
            ErrorCode::NoPrivateAddress => "no_private_address",
            ErrorCode::ListenFailed => "listen_failed",
            ErrorCode::KeychainFailed => "keychain_failed",
            ErrorCode::CaptureWouldBeLost => "capture_would_be_lost",
            ErrorCode::BadEmail => "bad_email",
            ErrorCode::BadServerUrl => "bad_server_url",
            ErrorCode::BwDownloadFailed => "bw_download_failed",
            ErrorCode::BwChecksumMismatch => "bw_checksum_mismatch",
            ErrorCode::BwUnreachable => "bw_unreachable",
            ErrorCode::BwSessionExpired => "bw_session_expired",
            ErrorCode::BwVaultReadFailed => "bw_vault_read_failed",
            ErrorCode::BwFailed => "bw_failed",
            ErrorCode::NotUnlocked => "not_unlocked",
            ErrorCode::NoBackup => "no_backup",
            ErrorCode::ExportFailed => "export_failed",
            ErrorCode::CleanupKeychainFailed => "cleanup_keychain_failed",
            ErrorCode::CleanupFailed => "cleanup_failed",
            ErrorCode::Internal => "internal",
        }
    }
}

/// Declares [`Reject`]: each refusal with its code and its sentence, and the list of all of
/// them, from one table, so that none can be added without both.
macro_rules! rejections {
    ($( $(#[$doc:meta])* $variant:ident => $code:ident, $sentence:expr; )+) => {
        /// One reason a command is refused. See the module documentation.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Reject {
            $( $(#[$doc])* $variant, )+
        }

        impl Reject {
            pub const ALL: &'static [Reject] = &[ $( Reject::$variant, )+ ];

            pub fn code(self) -> ErrorCode {
                match self {
                    $( Reject::$variant => ErrorCode::$code, )+
                }
            }

            /// What the person is told. Shown by the UI exactly as it is written here.
            pub fn sentence(self) -> &'static str {
                match self {
                    $( Reject::$variant => $sentence, )+
                }
            }
        }
    };
}

rejections! {
    // ---- the connection ----
    /// The address the proxy is bound to is no longer on any of this computer's interfaces.
    AddressChanged => AddressChanged,
        "This computer's network address has changed, so the iPhone or iPad can no longer reach the connection it was using. Restart the connection to carry on.";
    /// The address asked for is not (or is no longer) one of this computer's.
    AddressNotOurs => AddressChanged,
        "That address is not one of this computer's network addresses any more. Restart the connection to use the address it has now.";
    /// The address asked for is a public one.
    AddressPublic => AddressNotPrivate,
        "That address is reachable from the internet, so the connection cannot be opened on it. Use this computer's address on your home or office Wi-Fi.";
    /// No address was asked for and this computer has no private one to default to.
    NoPrivateAddress => NoPrivateAddress,
        "This computer is not on a home or office Wi-Fi network. Connect it to the same Wi-Fi as the iPhone or iPad and try again.";
    /// The text sent as an address is not one. The screen only ever sends addresses it was
    /// given, so this is the app's own fault.
    AddressInvalid => Internal,
        "The app asked for a network address that is not valid. Try again; if it keeps happening, quit the app and open it again.";
    ListenFailed => ListenFailed,
        "This computer could not open the connection for your iPhone or iPad. Check that Wi-Fi is switched on and that no other copy of this app is running, then try again.";
    /// The certificate key could not be put in the key store.
    KeychainFailed => KeychainFailed,
        "The certificate could not be created, because this computer's keychain did not take its key. Open Keychain Access, search for \"dev.somecorp.authexodus\", delete the item it finds, and try again.";
    MarkerNotWritten => Internal,
        "This app could not write to its own data folder, so the connection was not started. Check that this computer's disk is not full, then try again.";
    CaptureWouldBeLost => CaptureWouldBeLost,
        "A backup has already been captured on the current address. Changing the address means starting over.";

    // ---- unlocking ----
    ConnectionNotRunning => NoBackup,
        "The connection is not running, so there is no backup to unlock. Restart the connection and let Authy fetch your codes again.";
    BackupNotArrived => NoBackup,
        "The backup has not arrived from Authy yet.";
    UnlockOvertaken => NoBackup,
        "The connection was restarted while the backup was being unlocked, so there is nothing to unlock yet.";
    UnlockStopped => Internal,
        "Unlocking the backup stopped unexpectedly. Try again.";
    NotUnlocked => NotUnlocked,
        "The backup is not unlocked yet.";

    // ---- moving the accounts out ----
    NoSuchAccount => ExportFailed,
        "That account is not in the unlocked backup.";
    QrNotDrawn => ExportFailed,
        "A QR code could not be drawn for this account, because its details are too long to fit in one. Save a file for your app instead.";
    NoGoogleCodes => ExportFailed,
        "None of these accounts can go into a Google Authenticator transfer code. Scan them one by one instead.";
    GoogleQrNotDrawn => ExportFailed,
        "A Google Authenticator transfer code could not be drawn. Scan the accounts one by one instead.";
    NoFileForDestination => ExportFailed,
        "This app has no import file for that app. Use its QR codes instead.";
    SaveDialogClosed => ExportFailed,
        "The save window closed before a place was chosen. Try again.";
    UnsavableLocation => ExportFailed,
        "That place cannot be saved to. Choose a folder on this computer, such as Downloads.";
    FileNotSaved => ExportFailed,
        "The file could not be saved there. Choose another folder, such as Downloads, and try again.";

    // ---- Bitwarden ----
    BwDownloadFailed => BwDownloadFailed,
        "The Bitwarden tool could not be downloaded. Check this computer's internet connection and try again.";
    BwChecksumMismatch => BwChecksumMismatch,
        "The Bitwarden tool that was downloaded is not the file this app expects, so it was deleted and will not be used. Try again later, or save a Bitwarden import file instead and import it in Bitwarden yourself.";
    /// The program on disk is no longer the one that was verified.
    BwToolChanged => BwChecksumMismatch,
        "The Bitwarden tool on this computer has changed since this app checked it, so it was not run. Go back and let the app download it again.";
    BwNotPrepared => BwFailed,
        "The Bitwarden tool is not ready yet. Go back and let the app download it first.";
    /// The person stopped a download or a sign-in (`bw_cancel`).
    BwStopped => BwFailed,
        "That was stopped before it finished. Nothing was left behind.";
    BwUnsupportedPlatform => BwFailed,
        "This version of the app cannot use the Bitwarden tool on this computer. Save a Bitwarden import file instead and import it in Bitwarden yourself.";
    BadEmail => BadEmail,
        "That does not look like an email address.";
    BadServerUrl => BadServerUrl,
        "The server address must start with https:// and name a server, like the address you open your own Bitwarden web vault at.";
    BwUnreachable => BwUnreachable,
        "Bitwarden's server could not be reached, or it had a problem. Check this computer's internet connection, wait a moment, and try again.";
    BwSessionExpired => BwSessionExpired,
        "Your Bitwarden session has ended. Sign in again to carry on; what you chose is kept.";
    BwNotSignedIn => BwSessionExpired,
        "You are not signed in to Bitwarden. Sign in to carry on.";
    BwVaultReadFailed => BwVaultReadFailed,
        "You are signed in, but your Bitwarden vault could not be read. Try again.";
    BwSignInFailed => BwFailed,
        "The Bitwarden tool reported a problem while signing in. Check what you typed and try again.";
    BwToolFailed => BwFailed,
        "The Bitwarden tool reported a problem. Try again.";
    BwOvertaken => BwFailed,
        "The app was cleaned up while it was signing in to Bitwarden, so that sign-in was thrown away.";
    DecisionUnknownAccount => BwFailed,
        "One of the accounts to move is not in the unlocked backup. Nothing was changed.";
    DecisionUnknownLogin => BwFailed,
        "One of the chosen Bitwarden logins is not in your vault as this app last read it. Nothing was changed.";
    DecisionLoginHasCode => BwFailed,
        "One of the chosen Bitwarden logins already has a code of its own. Nothing was changed.";
    DecisionLoginTwice => BwFailed,
        "The same Bitwarden login was chosen for two accounts, and a login can hold only one code. Nothing was changed.";

    // ---- cleaning up ----
    CleanupKeychainFailed => CleanupKeychainFailed,
        "The certificate key could not be removed from this computer's keychain. To remove it by hand: open Keychain Access, search for \"dev.somecorp.authexodus\", and delete the item it finds. Then try again.";
    CleanupBwDataNotRemoved => CleanupFailed,
        "The folder the Bitwarden tool kept its data in could not be removed from this computer. Try again.";
    CleanupBwToolNotRemoved => CleanupFailed,
        "The Bitwarden tool this app downloaded could not be removed from this computer. Try again.";
    CleanupMarkerNotRemoved => CleanupFailed,
        "The app could not clear its own note that a cleanup is due, so it will ask again next time it is opened. Try again.";

    Internal => Internal,
        "Something went wrong inside the app. Try again; if it keeps happening, quit the app and open it again.";
}

/// A refused command. Reaches the UI as `"<code>: <sentence>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmdError(pub Reject);

impl CmdError {
    pub fn code(&self) -> ErrorCode {
        self.0.code()
    }

    pub fn sentence(&self) -> &'static str {
        self.0.sentence()
    }
}

impl From<Reject> for CmdError {
    fn from(reject: Reject) -> Self {
        CmdError(reject)
    }
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code().as_str(), self.sentence())
    }
}

impl std::error::Error for CmdError {}

impl Serialize for CmdError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// What the app was doing with Bitwarden when the tool failed: the same failure of the tool
/// means different things to the person at different moments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BwStage {
    Prepare,
    SignIn,
    /// Syncing and reading the vault.
    Read,
    SignOut,
}

/// The refusal for a Bitwarden failure at `stage`.
pub fn bw_reject(stage: BwStage, error: &BwError) -> Reject {
    match (error, stage) {
        (BwError::Server(_), _) => Reject::BwUnreachable,
        (BwError::SessionExpired, _) => Reject::BwSessionExpired,
        (BwError::Download(_), _) => Reject::BwDownloadFailed,
        (BwError::ChecksumMismatch, BwStage::Prepare) => Reject::BwChecksumMismatch,
        (BwError::ChecksumMismatch, _) => Reject::BwToolChanged,
        (BwError::BadEmail, _) => Reject::BadEmail,
        (BwError::BadServerUrl, _) => Reject::BadServerUrl,
        (BwError::Cancelled, _) => Reject::BwStopped,
        (BwError::UnsupportedPlatform, _) => Reject::BwUnsupportedPlatform,
        (BwError::Cli(_), BwStage::Prepare) => Reject::BwToolFailed,
        (BwError::Cli(_), BwStage::SignIn) => Reject::BwSignInFailed,
        (BwError::Cli(_), BwStage::Read) => Reject::BwVaultReadFailed,
        (BwError::Cli(_), BwStage::SignOut) => Reject::CleanupBwDataNotRemoved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::KEYCHAIN_SERVICE;
    use std::collections::BTreeSet;

    /// The codes the UI was told to expect, word for word.
    const CONTRACT: &[&str] = &[
        "address_changed",
        "address_not_private",
        "no_private_address",
        "listen_failed",
        "keychain_failed",
        "capture_would_be_lost",
        "bad_email",
        "bad_server_url",
        "bw_download_failed",
        "bw_checksum_mismatch",
        "bw_unreachable",
        "bw_session_expired",
        "bw_vault_read_failed",
        "bw_failed",
        "not_unlocked",
        "no_backup",
        "export_failed",
        "cleanup_keychain_failed",
        "cleanup_failed",
        "internal",
    ];

    #[test]
    fn the_codes_are_exactly_the_ones_the_ui_was_told() {
        let ours: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(ours, CONTRACT);
        let distinct: BTreeSet<&str> = ours.iter().copied().collect();
        assert_eq!(distinct.len(), CONTRACT.len(), "no code twice");
        // Every code is used by at least one refusal, and no refusal has a code outside them.
        let used: BTreeSet<&str> = Reject::ALL.iter().map(|r| r.code().as_str()).collect();
        assert_eq!(used, distinct);
    }

    /// Words with a dot between letters: `vault.example.com`, `session.json`.
    fn dotted_words(sentence: &str) -> Vec<&str> {
        sentence
            .split(|c: char| c.is_whitespace() || c == '"')
            .map(|word| word.trim_matches(|c: char| !c.is_alphanumeric()))
            .filter(|word| {
                word.split('.').count() > 1
                    && word
                        .split('.')
                        .all(|part| !part.is_empty() && part.chars().all(char::is_alphanumeric))
            })
            .collect()
    }

    #[test]
    fn every_refusal_is_a_plain_sentence_with_nothing_filled_in() {
        let mut seen = BTreeSet::new();
        for reject in Reject::ALL {
            let sentence = reject.sentence();
            assert!(seen.insert(sentence), "said twice: {sentence}");
            assert!(sentence.len() >= 20, "{reject:?}: {sentence:?}");
            assert!(
                sentence.starts_with(|c: char| c.is_ascii_uppercase()),
                "{sentence}"
            );
            assert!(sentence.ends_with('.'), "a whole sentence: {sentence}");
            assert_eq!(sentence.trim(), sentence);
            assert!(
                !sentence.contains("  ") && !sentence.contains('\n'),
                "{sentence}"
            );

            // No placeholder waiting to be filled in, and nothing that was.
            for mark in ['{', '}', '%', '$', '<', '>', '[', ']', '`', '=', '_'] {
                assert!(!sentence.contains(mark), "{mark:?} in {sentence}");
            }
            // No file path.
            assert!(
                !sentence.contains('\\') && !sentence.contains('~'),
                "{sentence}"
            );
            assert!(
                !sentence.replace("https://", "").contains('/'),
                "a path in {sentence}"
            );
            // No address of a server: the scheme is named once, never followed by a host.
            assert!(!sentence.contains("http://"), "{sentence}");
            for (at, _) in sentence.match_indices("https://") {
                let after = &sentence[at + "https://".len()..];
                assert!(after.starts_with(' '), "a server address in {sentence}");
            }
            // No host or file name. The one dotted word allowed is the name the person
            // searches Keychain Access for.
            for word in dotted_words(sentence) {
                assert_eq!(word, KEYCHAIN_SERVICE, "in {sentence}");
            }
            // No email address, no id, no number long enough to be one.
            assert!(!sentence.contains('@'), "{sentence}");
            let digits = sentence.chars().filter(char::is_ascii_digit).count();
            assert_eq!(digits, 0, "digits in {sentence}");
            // Not the language of the code: no type names, no "error:".
            for jargon in [
                "Err",
                "error",
                "panic",
                "stderr",
                "CLI",
                "null",
                "undefined",
            ] {
                assert!(!sentence.contains(jargon), "{jargon:?} in {sentence}");
            }
        }
        assert!(Reject::KeychainFailed.sentence().contains(KEYCHAIN_SERVICE));
        assert!(Reject::CleanupKeychainFailed
            .sentence()
            .contains(KEYCHAIN_SERVICE));
    }

    #[test]
    fn a_refusal_reaches_the_ui_as_its_code_then_its_sentence() {
        let error = CmdError(Reject::CaptureWouldBeLost);
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!(
                "capture_would_be_lost: A backup has already been captured on the current address. Changing the address means starting over."
            )
        );
        for reject in Reject::ALL {
            let sent = serde_json::to_value(CmdError(*reject)).unwrap();
            let sent = sent.as_str().expect("one string");
            let (code, sentence) = sent.split_once(": ").expect("code, colon, space, sentence");
            assert_eq!(code, reject.code().as_str());
            assert_eq!(sentence, reject.sentence());
            assert!(CONTRACT.contains(&code));
        }
    }

    #[test]
    fn a_bitwarden_failure_is_told_by_what_was_being_done() {
        use BwStage::*;
        let cli = BwError::Cli("Item \"Planted\" of sam@example.test failed".into());
        // Whatever the tool said stays out of the sentence.
        for stage in [Prepare, SignIn, Read, SignOut] {
            let sentence = bw_reject(stage, &cli).sentence();
            assert!(!sentence.contains("Planted") && !sentence.contains("sam@"));
        }
        assert_eq!(bw_reject(SignIn, &cli), Reject::BwSignInFailed);
        assert_eq!(bw_reject(Read, &cli), Reject::BwVaultReadFailed);
        assert_eq!(bw_reject(Read, &cli).code(), ErrorCode::BwVaultReadFailed);
        assert_eq!(
            bw_reject(Read, &BwError::SessionExpired).code(),
            ErrorCode::BwSessionExpired
        );
        assert_eq!(
            bw_reject(Read, &BwError::Server("503".into())).code(),
            ErrorCode::BwUnreachable
        );
        assert_eq!(
            bw_reject(Prepare, &BwError::Download("x".into())).code(),
            ErrorCode::BwDownloadFailed
        );
        // A bad download and a program swapped later are both a checksum failure, said
        // differently.
        assert_eq!(
            bw_reject(Prepare, &BwError::ChecksumMismatch),
            Reject::BwChecksumMismatch
        );
        assert_eq!(
            bw_reject(SignIn, &BwError::ChecksumMismatch),
            Reject::BwToolChanged
        );
        assert_eq!(
            bw_reject(SignIn, &BwError::ChecksumMismatch).code(),
            ErrorCode::BwChecksumMismatch
        );
        assert_eq!(
            bw_reject(SignIn, &BwError::BadEmail).code(),
            ErrorCode::BadEmail
        );
        assert_eq!(
            bw_reject(SignIn, &BwError::BadServerUrl).code(),
            ErrorCode::BadServerUrl
        );
        assert_eq!(bw_reject(Prepare, &BwError::Cancelled), Reject::BwStopped);
    }
}
