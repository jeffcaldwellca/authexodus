//! Pinned Bitwarden CLI download with SHA-256 check (package 1D).
//!
//! One release is pinned: the official `bitwarden/clients` release `cli-v2026.9.1`. The checksums
//! below are SHA-256 of the release zips. They were computed from the downloaded files on
//! 2026-10-02 and match the `digest` GitHub publishes for each release asset. A zip whose hash
//! differs is deleted and refused; nothing unverified is ever extracted or run.
//!
//! The folder is made readable by its owner only. Every call extracts `bw` afresh from the
//! verified zip, replacing whatever was there, and returns the SHA-256 of what it wrote, so
//! the caller can check the file again before using it (see `CliClient::expecting_sha256`).
//! A download larger than [`MAX_DOWNLOAD_BYTES`] is abandoned.
//!
//! Asset naming for this release: `bw-macos-arm64-VERSION.zip` is Apple silicon; the build with no
//! architecture in its name, `bw-macos-VERSION.zip`, is Intel (x64).
//!
//! The work reports how far it is ([`PrepareStage`]) and can be stopped ([`Cancel`]): a stopped
//! download or unpacking removes its partly written file before it returns.
//!
//! Not yet portable: this module is written for macOS. It compiles elsewhere, and on any
//! other system [`pinned_asset`] answers [`BwError::UnsupportedPlatform`] before anything is
//! downloaded. To port it:
//! * [`pinned_asset`] knows only the two macOS assets and their checksums (the release also
//!   has `bw-windows-VERSION.zip` and `bw-linux-VERSION.zip`);
//! * [`BINARY_NAME`] is `bw`; on Windows the entry in the zip and the program are `bw.exe`;
//! * the download folder is made owner-only with a Unix mode (`cfg(unix)`); Windows needs an
//!   ACL instead, and today gets nothing;
//! * the executable bit is set with a Unix mode (`cfg(unix)`); Windows needs none.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::{BwError, Cancel};

pub const CLI_VERSION: &str = "2026.9.1";
pub const RELEASE_TAG: &str = "cli-v2026.9.1";
pub const RELEASE_BASE_URL: &str = "https://github.com/bitwarden/clients/releases/download";

pub const MACOS_ARM64_ASSET: &str = "bw-macos-arm64-2026.9.1.zip";
pub const MACOS_ARM64_SHA256: &str =
    "9f52edf5fb855e277315c1106f1bae326a87c41b425a4c0e00fd1440e77fa0a6";
pub const MACOS_X64_ASSET: &str = "bw-macos-2026.9.1.zip";
pub const MACOS_X64_SHA256: &str =
    "7996558e562a7e5d1ef167f625e4dfde0230fe87246e01caf647aff5501ca658";

/// Connecting must succeed quickly; the whole download (42 to 44 MB) gets ten minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// File name of the extracted binary inside `dir`.
const BINARY_NAME: &str = "bw";
/// The release zip is 42 to 44 MB. Anything past this is not it, and is not written to disk.
pub const MAX_DOWNLOAD_BYTES: u64 = 400 * 1024 * 1024;

/// The extracted `bw` program and the SHA-256 (hex) of the file as it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliBinary {
    pub path: PathBuf,
    pub sha256: String,
}

/// How far [`ensure_cli_reporting`] has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareStage {
    /// The download is under way. Reported at the start and then once for every whole
    /// megabyte (2^20 bytes) received. `total` is the size the server announced, if it did.
    Downloading { received: u64, total: Option<u64> },
    /// The download (or the copy kept from an earlier run) is being hashed and unpacked.
    Checking,
    /// The verified program is in place.
    Ready,
}

/// The pinned asset for this machine: (file name, expected SHA-256 hex).
pub fn pinned_asset() -> Result<(&'static str, &'static str), BwError> {
    if !cfg!(target_os = "macos") {
        return Err(BwError::UnsupportedPlatform);
    }
    if cfg!(target_arch = "aarch64") {
        Ok((MACOS_ARM64_ASSET, MACOS_ARM64_SHA256))
    } else if cfg!(target_arch = "x86_64") {
        Ok((MACOS_X64_ASSET, MACOS_X64_SHA256))
    } else {
        Err(BwError::UnsupportedPlatform)
    }
}

/// Download (or reuse) the pinned, verified CLI and return the extracted `bw`.
pub async fn ensure_cli(dir: &Path) -> Result<CliBinary, BwError> {
    ensure_cli_reporting(dir, &|_| {}, &Cancel::new()).await
}

/// [`ensure_cli`], telling `progress` how far it is and stopping when `cancel` says so (with
/// [`BwError::Cancelled`], and with no partly written file left in `dir`).
pub async fn ensure_cli_reporting(
    dir: &Path,
    progress: &(dyn Fn(PrepareStage) + Send + Sync),
    cancel: &Cancel,
) -> Result<CliBinary, BwError> {
    let (asset, sha256) = pinned_asset()?;
    let base = format!("{RELEASE_BASE_URL}/{RELEASE_TAG}");
    ensure_cli_within(
        dir,
        &base,
        asset,
        sha256,
        MAX_DOWNLOAD_BYTES,
        progress,
        cancel,
    )
    .await
}

/// Same as [`ensure_cli`] with the download location and expected hash injected, so a test can
/// point it at a local file server. The URL fetched is `{base_url}/{asset}`.
pub async fn ensure_cli_from(
    dir: &Path,
    base_url: &str,
    asset: &str,
    expected_sha256: &str,
) -> Result<CliBinary, BwError> {
    ensure_cli_within(
        dir,
        base_url,
        asset,
        expected_sha256,
        MAX_DOWNLOAD_BYTES,
        &|_| {},
        &Cancel::new(),
    )
    .await
}

/// [`ensure_cli_from`] with the size limit, the progress callback and the stop signal
/// injected, so a test need not serve 400 MB.
#[doc(hidden)]
pub async fn ensure_cli_within(
    dir: &Path,
    base_url: &str,
    asset: &str,
    expected_sha256: &str,
    max_bytes: u64,
    progress: &(dyn Fn(PrepareStage) + Send + Sync),
    cancel: &Cancel,
) -> Result<CliBinary, BwError> {
    if cancel.is_cancelled() {
        return Err(BwError::Cancelled);
    }
    let io = |what: &str, e: std::io::Error| BwError::Download(format!("{what}: {e}"));
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| io("creating the download folder", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|e| io("making the download folder private", e))?;
    }
    let zip_path = dir.join(asset);

    // A zip kept from an earlier run is trusted only if it still hashes correctly.
    let kept = tokio::fs::try_exists(&zip_path).await.unwrap_or(false);
    if kept {
        progress(PrepareStage::Checking);
    }
    let have_good_zip = match sha256_of_file(&zip_path).await {
        Ok(h) => h.eq_ignore_ascii_case(expected_sha256),
        Err(_) => false,
    };
    if !have_good_zip {
        // Removes the partly written file however this ends, unless it becomes the zip.
        let mut part = Partial::new(dir.join(format!("{asset}.part")));
        let url = format!("{}/{asset}", base_url.trim_end_matches('/'));
        let actual = fetch(&url, &part.path, max_bytes, progress, cancel).await?;
        progress(PrepareStage::Checking);
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            return Err(BwError::ChecksumMismatch);
        }
        tokio::fs::rename(&part.path, &zip_path)
            .await
            .map_err(|e| io("saving the download", e))?;
        part.keep();
    }

    let dest = dir.join(BINARY_NAME);
    let (zip_path2, dest2, cancel2) = (zip_path.clone(), dest.clone(), cancel.clone());
    // Waited for even when stopped: the unpacking sees the signal itself, within one block,
    // so nothing is still writing once this returns.
    let sha256 = tokio::task::spawn_blocking(move || extract_binary(&zip_path2, &dest2, &cancel2))
        .await
        .map_err(|e| BwError::Download(format!("unpacking: {e}")))??;
    progress(PrepareStage::Ready);
    Ok(CliBinary { path: dest, sha256 })
}

/// A file that is removed when this is dropped, unless [`Partial::keep`] was called: a
/// download or an unpacking that fails, is stopped, or is simply dropped half-way leaves
/// nothing behind.
struct Partial {
    path: PathBuf,
    keep: bool,
}

impl Partial {
    fn new(path: PathBuf) -> Partial {
        Partial { path, keep: false }
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Stream `url` into `path`, hashing as it goes. Returns the SHA-256 hex. `path` must not
/// exist when the writing starts (a leftover is removed first; a symbolic link planted there
/// is refused, not followed), and no more than `max_bytes` are accepted.
async fn fetch(
    url: &str,
    path: &Path,
    max_bytes: u64,
    progress: &(dyn Fn(PrepareStage) + Send + Sync),
    cancel: &Cancel,
) -> Result<String, BwError> {
    const MEGABYTE: u64 = 1024 * 1024;
    let too_large = || BwError::Download("the download is larger than expected".into());
    let dl = |e: &dyn std::fmt::Display| BwError::Download(e.to_string());
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .build()
        .map_err(|e| dl(&e))?;
    let mut resp = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(BwError::Cancelled),
        sent = client.get(url).send() => sent.map_err(|e| dl(&e))?,
    };
    if !resp.status().is_success() {
        return Err(BwError::Download(format!(
            "server answered {}",
            resp.status()
        )));
    }
    let total = resp.content_length();
    if total.is_some_and(|len| len > max_bytes) {
        return Err(too_large());
    }
    let _ = tokio::fs::remove_file(path).await;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(|e| dl(&e))?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    progress(PrepareStage::Downloading { received, total });
    loop {
        let chunk = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(BwError::Cancelled),
            chunk = resp.chunk() => chunk.map_err(|e| dl(&e))?,
        };
        let Some(chunk) = chunk else { break };
        let before = received / MEGABYTE;
        received += chunk.len() as u64;
        if received > max_bytes {
            return Err(too_large());
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| dl(&e))?;
        if received / MEGABYTE != before {
            progress(PrepareStage::Downloading { received, total });
        }
    }
    file.flush().await.map_err(|e| dl(&e))?;
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) async fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut f = std::fs::File::open(path)?;
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h)?;
        Ok(hex::encode(h.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Pull the single `bw` entry out of the verified zip, make it executable, and put it in
/// place of whatever `dest` was. Returns the SHA-256 hex of the bytes written. The temporary
/// file must be new: a leftover is removed first, and a symbolic link planted at its name is
/// refused, not followed. It is removed again if the unpacking fails or is stopped.
fn extract_binary(zip_path: &Path, dest: &Path, cancel: &Cancel) -> Result<String, BwError> {
    let err = |e: &dyn std::fmt::Display| BwError::Download(format!("unpacking: {e}"));
    let file = std::fs::File::open(zip_path).map_err(|e| err(&e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| err(&e))?;
    let mut entry = archive
        .by_name(BINARY_NAME)
        .map_err(|_| BwError::Download("the download did not contain the bw program".into()))?;
    let tmp = dest.with_extension("partial");
    let _ = std::fs::remove_file(&tmp);
    let mut hasher = Sha256::new();
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| err(&e))?;
    // Only now that the file is ours: removed again unless the unpacking completes.
    let mut partial = Partial::new(tmp.clone());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if cancel.is_cancelled() {
            return Err(BwError::Cancelled);
        }
        let n = std::io::Read::read(&mut entry, &mut buf).map_err(|e| err(&e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut out, &buf[..n]).map_err(|e| err(&e))?;
    }
    out.sync_all().map_err(|e| err(&e))?;
    drop(out);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| err(&e))?;
    }
    if cancel.is_cancelled() {
        return Err(BwError::Cancelled);
    }
    std::fs::rename(&tmp, dest).map_err(|e| err(&e))?;
    partial.keep();
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_checksums_are_well_formed() {
        for h in [MACOS_ARM64_SHA256, MACOS_X64_SHA256] {
            assert_eq!(h.len(), 64);
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        }
        assert_ne!(MACOS_ARM64_SHA256, MACOS_X64_SHA256);
    }
}
