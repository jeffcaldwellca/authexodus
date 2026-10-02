//! Pinned Bitwarden CLI download with SHA-256 check (package 1D).
//!
//! One release is pinned: the official `bitwarden/clients` release `cli-v2026.9.1`. The checksums
//! below are SHA-256 of the release zips. They were computed from the downloaded files on
//! 2026-10-02 and match the `digest` GitHub publishes for each release asset. A zip whose hash
//! differs is deleted and refused; nothing unverified is ever extracted or run.
//!
//! Asset naming for this release: `bw-macos-arm64-VERSION.zip` is Apple silicon; the build with no
//! architecture in its name, `bw-macos-VERSION.zip`, is Intel (x64).

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::BwError;

pub const CLI_VERSION: &str = "2026.9.1";
pub const RELEASE_TAG: &str = "cli-v2026.9.1";
pub const RELEASE_BASE_URL: &str = "https://github.com/bitwarden/clients/releases/download";

pub const MACOS_ARM64_ASSET: &str = "bw-macos-arm64-2026.9.1.zip";
pub const MACOS_ARM64_SHA256: &str =
    "9f52edf5fb855e277315c1106f1bae326a87c41b425a4c0e00fd1440e77fa0a6";
pub const MACOS_X64_ASSET: &str = "bw-macos-2026.9.1.zip";
pub const MACOS_X64_SHA256: &str =
    "7996558e562a7e5d1ef167f625e4dfde0230fe87246e01caf647aff5501ca658";

/// Connecting must succeed quickly; the whole ~130 MB download gets ten minutes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// File name of the extracted binary inside `dir`.
const BINARY_NAME: &str = "bw";

/// The pinned asset for this machine: (file name, expected SHA-256 hex).
pub fn pinned_asset() -> Result<(&'static str, &'static str), BwError> {
    if !cfg!(target_os = "macos") {
        return Err(BwError::Download(
            "this version of the app only downloads the Bitwarden tool for macOS".into(),
        ));
    }
    if cfg!(target_arch = "aarch64") {
        Ok((MACOS_ARM64_ASSET, MACOS_ARM64_SHA256))
    } else if cfg!(target_arch = "x86_64") {
        Ok((MACOS_X64_ASSET, MACOS_X64_SHA256))
    } else {
        Err(BwError::Download("unsupported processor".into()))
    }
}

/// Download (or reuse) the pinned, verified CLI and return the path to `bw`.
pub async fn ensure_cli(dir: &Path) -> Result<PathBuf, BwError> {
    let (asset, sha256) = pinned_asset()?;
    let base = format!("{RELEASE_BASE_URL}/{RELEASE_TAG}");
    ensure_cli_from(dir, &base, asset, sha256).await
}

/// Same as [`ensure_cli`] with the download location and expected hash injected, so a test can
/// point it at a local file server. The URL fetched is `{base_url}/{asset}`.
pub async fn ensure_cli_from(
    dir: &Path,
    base_url: &str,
    asset: &str,
    expected_sha256: &str,
) -> Result<PathBuf, BwError> {
    let io = |what: &str, e: std::io::Error| BwError::Download(format!("{what}: {e}"));
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| io("creating the download folder", e))?;
    let zip_path = dir.join(asset);

    // A zip kept from an earlier run is trusted only if it still hashes correctly.
    let have_good_zip = match sha256_of_file(&zip_path).await {
        Ok(h) => h.eq_ignore_ascii_case(expected_sha256),
        Err(_) => false,
    };
    if !have_good_zip {
        let part = dir.join(format!("{asset}.part"));
        let url = format!("{}/{asset}", base_url.trim_end_matches('/'));
        let actual = match fetch(&url, &part).await {
            Ok(h) => h,
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                return Err(e);
            }
        };
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(BwError::ChecksumMismatch);
        }
        tokio::fs::rename(&part, &zip_path)
            .await
            .map_err(|e| io("saving the download", e))?;
    }

    let dest = dir.join(BINARY_NAME);
    let (zip_path2, dest2) = (zip_path.clone(), dest.clone());
    tokio::task::spawn_blocking(move || extract_binary(&zip_path2, &dest2))
        .await
        .map_err(|e| BwError::Download(format!("unpacking: {e}")))??;
    Ok(dest)
}

/// Stream `url` into `path`, hashing as it goes. Returns the SHA-256 hex.
async fn fetch(url: &str, path: &Path) -> Result<String, BwError> {
    let dl = |e: &dyn std::fmt::Display| BwError::Download(e.to_string());
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .build()
        .map_err(|e| dl(&e))?;
    let mut resp = client.get(url).send().await.map_err(|e| dl(&e))?;
    if !resp.status().is_success() {
        return Err(BwError::Download(format!(
            "server answered {}",
            resp.status()
        )));
    }
    let mut file = tokio::fs::File::create(path).await.map_err(|e| dl(&e))?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| dl(&e))? {
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| dl(&e))?;
    }
    file.flush().await.map_err(|e| dl(&e))?;
    Ok(hex::encode(hasher.finalize()))
}

async fn sha256_of_file(path: &Path) -> std::io::Result<String> {
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

/// Pull the single `bw` entry out of the verified zip and make it executable.
fn extract_binary(zip_path: &Path, dest: &Path) -> Result<(), BwError> {
    let err = |e: &dyn std::fmt::Display| BwError::Download(format!("unpacking: {e}"));
    let file = std::fs::File::open(zip_path).map_err(|e| err(&e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| err(&e))?;
    let mut entry = archive
        .by_name(BINARY_NAME)
        .map_err(|_| BwError::Download("the download did not contain the bw program".into()))?;
    let tmp = dest.with_extension("partial");
    {
        let mut out = std::fs::File::create(&tmp).map_err(|e| err(&e))?;
        std::io::copy(&mut entry, &mut out).map_err(|e| err(&e))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| err(&e))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| err(&e))?;
    Ok(())
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
