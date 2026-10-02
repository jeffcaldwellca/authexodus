//! Bitwarden integration tests against a fake client (package 1D). Synthetic data only.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use authexodus_core::bitwarden::apply::{kept_same_code, kept_same_title, skipped_other_code};
use authexodus_core::bitwarden::cli::{classify_failure, parse_login_items};
use authexodus_core::bitwarden::download::{ensure_cli_from, ensure_cli_within, PrepareStage};
use authexodus_core::bitwarden::{
    apply, check_login_input, is_vault_id, propose, BwClient, BwError, Cancel, CliClient, CodeMark,
    Confidence, Decision, LoginOutcome, Region, SetTotp, VaultLogin,
};
use authexodus_core::types::{Secret, Token};

// ---------- builders ----------

fn tok(id: &str, name: &str, issuer: Option<&str>, username: Option<&str>) -> Token {
    Token {
        id: id.into(),
        title: match issuer {
            Some(i) => format!("{i} ({name})"),
            None => name.into(),
        },
        name: name.into(),
        issuer: issuer.map(Into::into),
        username: username.map(Into::into),
        secret: Secret::new("JBSWY3DPEHPK3PXP".into()),
        digits: 6,
        period: 30,
    }
}

fn login(
    id: &str,
    name: &str,
    username: Option<&str>,
    hosts: &[&str],
    has_totp: bool,
) -> VaultLogin {
    VaultLogin {
        id: id.into(),
        name: name.into(),
        username: username.map(Into::into),
        hosts: hosts.iter().map(|h| h.to_string()).collect(),
        has_totp,
        // A login that came with a code holds somebody else's, not one of the tests' tokens'.
        code: has_totp
            .then(|| CodeMark::of_secret("KRUGKIDDN5SGKIDUNBQXIIDXMFZSA5DIMVZGK"))
            .flatten(),
    }
}

fn attach(id: &str) -> Decision {
    Decision::Attach { item_id: id.into() }
}

// ---------- FakeBw ----------

#[derive(Default)]
struct FakeState {
    logins: Vec<VaultLogin>,
    totp_values: HashMap<String, String>,
    folder_titles: Vec<String>,
    /// The code of each login created in the import folder.
    created_codes: Vec<String>,
    writes: usize,
    /// (nth write that fails, error, whether the server kept the write anyway)
    fail: Option<(usize, BwError, bool)>,
    synced: usize,
}

struct FakeBw(Mutex<FakeState>);

impl FakeBw {
    fn new(logins: Vec<VaultLogin>) -> FakeBw {
        FakeBw(Mutex::new(FakeState {
            logins,
            ..Default::default()
        }))
    }
    fn failing(self, nth: usize, err: BwError, persist: bool) -> FakeBw {
        self.0.lock().unwrap().fail = Some((nth, err, persist));
        self
    }
    fn clear_failure(&self) {
        self.0.lock().unwrap().fail = None;
    }
    fn writes(&self) -> usize {
        self.0.lock().unwrap().writes
    }
    fn titles(&self) -> Vec<String> {
        self.0.lock().unwrap().folder_titles.clone()
    }
    fn has_totp(&self, id: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .logins
            .iter()
            .find(|l| l.id == id)
            .unwrap()
            .has_totp
    }
    fn totp_of(&self, id: &str) -> Option<String> {
        self.0.lock().unwrap().totp_values.get(id).cloned()
    }
}

/// Counts the write; returns Some(err) when this write is the one that fails.
fn tick(s: &mut FakeState) -> Option<(BwError, bool)> {
    s.writes += 1;
    match &s.fail {
        Some((n, e, persist)) if *n == s.writes => Some((e.clone(), *persist)),
        _ => None,
    }
}

#[async_trait]
impl BwClient for FakeBw {
    async fn login(
        &mut self,
        _: &str,
        _: &str,
        _: &Region,
        _: Option<&str>,
    ) -> Result<LoginOutcome, BwError> {
        Ok(LoginOutcome::Ok)
    }
    async fn login_with_api_key(
        &mut self,
        _: &str,
        _: &str,
        _: &str,
        _: &Region,
    ) -> Result<LoginOutcome, BwError> {
        Ok(LoginOutcome::Ok)
    }
    async fn sync(&self) -> Result<(), BwError> {
        self.0.lock().unwrap().synced += 1;
        Ok(())
    }
    async fn list_logins(&self) -> Result<Vec<VaultLogin>, BwError> {
        Ok(self.0.lock().unwrap().logins.clone())
    }
    async fn import_folder_titles(&self) -> Result<Vec<String>, BwError> {
        Ok(self.0.lock().unwrap().folder_titles.clone())
    }
    async fn set_totp(&self, item_id: &str, otpauth: &str) -> Result<SetTotp, BwError> {
        let mut s = self.0.lock().unwrap();
        let wanted = CodeMark::of_totp_field(otpauth);
        let existing = s
            .logins
            .iter()
            .find(|l| l.id == item_id)
            .map(|l| (l.has_totp, l.code));
        match existing {
            None => return Err(BwError::Cli("no such item".into())),
            // As the real client does: the same key is done, another key is left alone.
            Some((true, held)) if held.is_some() && held == wanted => {
                return Ok(SetTotp::AlreadySet)
            }
            Some((true, _)) => return Ok(SetTotp::AlreadyHasCode),
            Some((false, _)) => {}
        }
        let failure = tick(&mut s);
        if failure.as_ref().is_none_or(|(_, persist)| *persist) {
            s.totp_values.insert(item_id.into(), otpauth.into());
            let login = s.logins.iter_mut().find(|l| l.id == item_id).unwrap();
            login.has_totp = true;
            login.code = wanted;
        }
        match failure {
            Some((e, _)) => Err(e),
            None => Ok(SetTotp::Attached),
        }
    }
    async fn create_in_import_folder(
        &self,
        title: &str,
        _: Option<&str>,
        otpauth: &str,
    ) -> Result<(), BwError> {
        let mut s = self.0.lock().unwrap();
        let failure = tick(&mut s);
        if failure.as_ref().is_none_or(|(_, persist)| *persist) {
            s.folder_titles.push(title.into());
            s.created_codes.push(otpauth.into());
        }
        match failure {
            Some((e, _)) => Err(e),
            None => Ok(()),
        }
    }
    async fn logout_and_wipe(&mut self) -> Result<(), BwError> {
        Ok(())
    }
}

fn no_progress() -> impl Fn(String) + Sync {
    |_| {}
}

// ---------- propose ----------

#[test]
fn exact_service_and_username_is_high_confidence() {
    let vault = vec![
        login(
            "gl",
            "GitLab",
            Some("sam@example.test"),
            &["gitlab.com"],
            false,
        ),
        login(
            "gh",
            "GitHub",
            Some("sam@example.test"),
            &["github.com"],
            false,
        ),
        login(
            "gh2",
            "GitHub work",
            Some("other@example.test"),
            &["github.com"],
            false,
        ),
    ];
    let p = propose(
        &[tok(
            "t1",
            "GitHub",
            Some("GitHub"),
            Some("sam@example.test"),
        )],
        &vault,
    );
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].token_id, "t1");
    assert_eq!(p[0].decision, attach("gh"));
    assert_eq!(p[0].confidence, Confidence::High);
}

#[test]
fn two_logins_for_one_service_is_low_with_both_candidates() {
    // Three logins for one service, and nothing in the token says which.
    let vault = vec![
        login(
            "s1",
            "Shopify (shop one)",
            Some("a@example.test"),
            &["one.myshopify.com"],
            false,
        ),
        login(
            "s2",
            "Shopify (shop two)",
            Some("b@example.test"),
            &["two.myshopify.com"],
            false,
        ),
        login(
            "s3",
            "Shopify (shop three)",
            Some("c@example.test"),
            &["admin.shopify.com"],
            false,
        ),
        login("x", "Unrelated", None, &["example.test"], false),
    ];
    let p = propose(&[tok("t1", "Shopify", Some("Shopify"), None)], &vault);
    assert_eq!(p[0].confidence, Confidence::Low);
    assert!(matches!(p[0].decision, Decision::Attach { .. }));
    let got: HashSet<&str> = p[0].candidates.iter().map(String::as_str).collect();
    assert_eq!(got, HashSet::from(["s1", "s2", "s3"]));
}

#[test]
fn login_with_existing_code_is_never_chosen() {
    let vault = vec![login(
        "gh",
        "GitHub",
        Some("sam@example.test"),
        &["github.com"],
        true,
    )];
    let p = propose(
        &[tok(
            "t1",
            "GitHub",
            Some("GitHub"),
            Some("sam@example.test"),
        )],
        &vault,
    );
    assert_eq!(p[0].decision, Decision::CreateNew);
    assert!(
        p[0].candidates.contains(&"gh".to_string()),
        "listed as a candidate"
    );

    // With a second, code-less login for the same service, that one is chosen instead.
    let vault = vec![
        login(
            "gh",
            "GitHub",
            Some("sam@example.test"),
            &["github.com"],
            true,
        ),
        login("gh2", "GitHub (old)", None, &["github.com"], false),
    ];
    let p = propose(
        &[tok(
            "t1",
            "GitHub",
            Some("GitHub"),
            Some("sam@example.test"),
        )],
        &vault,
    );
    assert_eq!(p[0].decision, attach("gh2"));
}

#[test]
fn no_match_creates_new() {
    let vault = vec![
        login(
            "a",
            "Bank",
            Some("sam@example.test"),
            &["bank.example"],
            false,
        ),
        login("b", "Router", None, &["192.168.0.1"], false),
    ];
    // Same username as the bank login, but the service does not match: never attach on that alone.
    let p = propose(
        &[tok(
            "t1",
            "Quillpad",
            Some("Quillpad"),
            Some("sam@example.test"),
        )],
        &vault,
    );
    assert_eq!(p[0].decision, Decision::CreateNew);
    assert_eq!(p[0].confidence, Confidence::High);
    assert!(p[0].candidates.is_empty());
}

#[test]
fn one_login_is_not_given_to_two_tokens() {
    let vault = vec![login(
        "gh",
        "GitHub",
        Some("a@example.test"),
        &["github.com"],
        false,
    )];
    // The weaker claimant is listed first on purpose.
    let tokens = [
        tok("weak", "GitHub", Some("GitHub"), Some("b@example.test")),
        tok("strong", "GitHub", Some("GitHub"), Some("a@example.test")),
    ];
    let p = propose(&tokens, &vault);
    assert_eq!(
        p[0].token_id, "weak",
        "output keeps the order of the tokens"
    );
    assert_eq!(p[1].decision, attach("gh"));
    assert_eq!(p[1].confidence, Confidence::High);
    assert_eq!(p[0].decision, Decision::CreateNew);
    assert_eq!(p[0].confidence, Confidence::Low);
    assert!(p[0].candidates.contains(&"gh".to_string()));
    let attached: Vec<_> = p
        .iter()
        .filter(|x| matches!(x.decision, Decision::Attach { .. }))
        .collect();
    assert_eq!(attached.len(), 1);
}

#[test]
fn alias_table_matches_aws_and_microsoft() {
    let vault = vec![
        login(
            "aws",
            "AWS Console",
            None,
            &["signin.aws.amazon.com"],
            false,
        ),
        login(
            "ms",
            "Outlook",
            Some("sam@example.test"),
            &["login.live.com"],
            false,
        ),
        login("g", "Mail", None, &["mail.google.com"], false),
        login("other", "Zebra", None, &["zebra.example"], false),
    ];
    let tokens = [
        tok(
            "t1",
            "Amazon Web Services",
            Some("Amazon Web Services"),
            None,
        ),
        tok(
            "t2",
            "Microsoft",
            Some("Microsoft"),
            Some("sam@example.test"),
        ),
        tok("t3", "Gmail", Some("Gmail"), None),
    ];
    let p = propose(&tokens, &vault);
    assert_eq!(p[0].decision, attach("aws"));
    assert_eq!(p[1].decision, attach("ms"));
    assert_eq!(p[2].decision, attach("g"));
}

// ---------- apply ----------

fn twelve() -> (Vec<Token>, Vec<VaultLogin>, Vec<(String, Decision)>) {
    // Twelve accounts, so twelve different keys.
    let tokens: Vec<Token> = distinct(
        (0..12)
            .map(|i| tok(&format!("t{i}"), &format!("Svc{i}"), None, None))
            .collect(),
    );
    let vault: Vec<VaultLogin> = (0..6)
        .map(|i| login(&format!("L{i}"), &format!("Svc{i}"), None, &[], false))
        .collect();
    let decisions = (0..12)
        .map(|i| {
            let d = if i < 6 {
                attach(&format!("L{i}"))
            } else {
                Decision::CreateNew
            };
            (format!("t{i}"), d)
        })
        .collect();
    (tokens, vault, decisions)
}

#[tokio::test]
async fn apply_never_overwrites_existing_code() {
    let fake = FakeBw::new(vec![
        login("L0", "Has Code", None, &[], true),
        login("L1", "Free", None, &[], false),
    ]);
    let tokens = [
        tok("t0", "Has Code", None, None),
        tok("t1", "Free", None, None),
    ];
    let decisions = vec![
        ("t0".to_string(), attach("L0")),
        ("t1".to_string(), attach("L1")),
    ];
    let lines = Mutex::new(Vec::new());
    let r = apply(&fake, &tokens, &decisions, &|line| {
        lines.lock().unwrap().push(line)
    })
    .await;
    // The person is told why in the run's own log.
    assert!(lines
        .into_inner()
        .unwrap()
        .contains(&skipped_other_code("Has Code")));
    assert_eq!(r.attached, 1);
    // Nothing was written for it, so it stays only in Authy: that is a skip, and it is not
    // listed among the codes that are already in Bitwarden.
    assert_eq!(r.skipped, 1);
    assert_eq!(r.kept, Vec::<String>::new());
    assert_eq!(r.failed, None);
    assert_eq!(
        fake.totp_of("L0"),
        None,
        "the existing code was not touched"
    );
    assert!(fake
        .totp_of("L1")
        .unwrap()
        .starts_with("otpauth://totp/Free?secret=JBSWY3DPEHPK3PXP"));
    assert_eq!(fake.writes(), 1);
}

#[tokio::test]
async fn apply_resumes_after_failure() {
    for persisted in [false, true] {
        let (tokens, vault, decisions) = twelve();
        let fake = FakeBw::new(vault).failing(
            10,
            BwError::Server("503 Service Unavailable".into()),
            persisted,
        );

        let first = apply(&fake, &tokens, &decisions, &no_progress()).await;
        let msg = first.failed.expect("the 10th write failed");
        assert!(
            !msg.contains("503"),
            "plain message, not the raw error: {msg}"
        );
        assert_eq!(first.attached, 6);
        assert_eq!(first.created, 3, "stopped at the first error");

        fake.clear_failure();
        let second = apply(&fake, &tokens, &decisions, &no_progress()).await;
        assert_eq!(second.failed, None);

        // Every token is present exactly once: six attached, six created, no duplicates.
        for i in 0..6 {
            assert!(fake.has_totp(&format!("L{i}")), "L{i}");
        }
        let titles = fake.titles();
        for i in 6..12 {
            let n = titles.iter().filter(|t| **t == format!("Svc{i}")).count();
            assert_eq!(
                n, 1,
                "Svc{i} created {n} times (server kept failed write: {persisted})"
            );
        }
        assert_eq!(titles.len(), 6);
        // A third run changes nothing in the vault.
        let writes = fake.writes();
        let third = apply(&fake, &tokens, &decisions, &no_progress()).await;
        assert_eq!(third.created, 0);
        assert_eq!(third.failed, None);
        assert_eq!(third.attached, 6, "the six attaches are reported as done");
        assert_eq!(
            third.kept.len(),
            6,
            "the six created earlier: {:?}",
            third.kept
        );
        assert_eq!(third.skipped, 0);
        assert_eq!(fake.writes(), writes);
    }
}

#[tokio::test]
async fn session_expiry_stops_with_plain_message() {
    let (tokens, vault, decisions) = twelve();
    let fake = FakeBw::new(vault).failing(3, BwError::SessionExpired, false);
    let r = apply(&fake, &tokens, &decisions, &no_progress()).await;
    let msg = r.failed.expect("stopped");
    assert!(msg.to_lowercase().contains("sign in again"), "{msg}");
    assert_eq!(
        r.error,
        Some(BwError::SessionExpired),
        "the caller can tell an ended session from any other failure"
    );
    assert!(!msg.contains("SessionExpired"));
    assert_eq!(r.attached, 2);
    assert_eq!(fake.writes(), 3, "nothing is attempted after the failure");
}

#[tokio::test]
async fn only_a_chosen_skip_is_counted_as_skipped() {
    let fake = FakeBw::new(vec![]);
    fake.0
        .lock()
        .unwrap()
        .folder_titles
        .push("Already There".into());
    let tokens = [
        tok("a", "Already There", None, None),
        tok("b", "Skipped", None, None),
    ];
    let decisions = vec![
        ("a".to_string(), Decision::CreateNew),
        ("b".to_string(), Decision::Skip),
    ];
    let r = apply(&fake, &tokens, &decisions, &no_progress()).await;
    assert_eq!((r.created, r.skipped, r.failed), (0, 1, None));
    assert_eq!(
        r.kept,
        vec![kept_same_title("Already There")],
        "what is already in Bitwarden is said so, not counted with the skipped"
    );
    assert_eq!(r.error, None);
    assert_eq!(fake.0.lock().unwrap().synced, 1, "syncs first");

    // A row whose token is not in the backup is refused, and that is counted as skipped.
    let r = apply(
        &fake,
        &tokens,
        &[("nobody".to_string(), Decision::CreateNew)],
        &no_progress(),
    )
    .await;
    assert_eq!((r.created, r.skipped, r.kept.len()), (0, 1, 0));
}

// ---------- download ----------

fn bw_zip(contents: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut w = zip::ZipWriter::new(&mut buf);
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    w.start_file("bw", opts).unwrap();
    w.write_all(contents).unwrap();
    w.finish().unwrap();
    buf.into_inner()
}

/// Serve `body` for any GET on a local port; returns the base URL.
async fn file_server(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/zip\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[tokio::test]
async fn checksum_mismatch_refuses_the_binary() {
    let zip = bw_zip(b"#!/bin/sh\necho pretend bw\n");
    let base = file_server(zip).await;
    let dir = tempfile::tempdir().unwrap();
    let wrong = sha256_hex(b"something else entirely");
    let err = ensure_cli_from(dir.path(), &base, "bw-test.zip", &wrong)
        .await
        .unwrap_err();
    assert_eq!(err, BwError::ChecksumMismatch);
    assert!(!dir.path().join("bw").exists(), "nothing was extracted");
    assert!(
        !dir.path().join("bw-test.zip").exists(),
        "the bad download was not kept"
    );
    assert!(!dir.path().join("bw-test.zip.part").exists());
}

#[tokio::test]
async fn matching_checksum_extracts_an_executable() {
    let zip = bw_zip(b"#!/bin/sh\necho pretend bw\n");
    let expected = sha256_hex(&zip);
    let base = file_server(zip).await;
    let dir = tempfile::tempdir().unwrap();
    let path = ensure_cli_from(dir.path(), &base, "bw-test.zip", &expected)
        .await
        .unwrap();
    assert_eq!(path.path, dir.path().join("bw"));
    assert_eq!(
        std::fs::read(&path.path).unwrap(),
        b"#!/bin/sh\necho pretend bw\n"
    );
    assert_eq!(
        path.sha256,
        sha256_hex(b"#!/bin/sh\necho pretend bw\n"),
        "the hash of the extracted program is handed back"
    );
    let path = path.path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o111,
            0o111
        );
    }
    // A second call reuses the verified zip even with the server gone.
    let again = ensure_cli_from(dir.path(), "http://127.0.0.1:1", "bw-test.zip", &expected)
        .await
        .unwrap();
    assert_eq!(again.path, path);
}

#[tokio::test]
async fn unreachable_server_is_a_download_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = ensure_cli_from(
        dir.path(),
        "http://127.0.0.1:1",
        "bw-test.zip",
        &sha256_hex(b"x"),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, BwError::Download(_)), "{err:?}");
}

/// Downloads the real pinned release (about 130 MB) and checks it against the checksums in the
/// source. Run by hand: `cargo test -p authexodus-core --test bitwarden -- --ignored live`.
#[tokio::test]
#[ignore]
async fn live_download_matches_pinned_checksum() {
    let dir = tempfile::tempdir().unwrap();
    let path = authexodus_core::bitwarden::ensure_cli(dir.path())
        .await
        .unwrap();
    assert!(path.path.exists());
}

// ---------- CliClient ----------

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bitwarden")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_dir().join(name)).unwrap()
}

#[test]
fn cli_client_parses_real_list_output() {
    let logins = parse_login_items(&fixture("list_items.json")).unwrap();
    // Cards and notes are dropped; the four logins remain.
    assert_eq!(logins.len(), 4);

    let acme = &logins[0];
    assert_eq!(acme.name, "Acme Storefront");
    assert_eq!(acme.username.as_deref(), Some("owner@acme.example"));
    assert_eq!(
        acme.hosts,
        vec!["acmestore.example", "admin.acmestore.example"],
        "scheme-less uri gets a host, sorted and de-duplicated"
    );
    assert!(acme.has_totp);

    let router = &logins[1];
    assert_eq!(router.username, None, "an empty username is no username");
    assert_eq!(
        router.hosts,
        vec!["10.0.0.1", "192.168.0.1"],
        "IP addresses are hosts too"
    );
    assert!(!router.has_totp);

    let bare = &logins[2];
    assert_eq!(
        (bare.username.clone(), bare.hosts.clone(), bare.has_totp),
        (None, vec![], false)
    );

    let blank = &logins[3];
    assert_eq!(blank.username.as_deref(), Some("pat@example.test"));
    assert!(blank.hosts.is_empty(), "null and empty uris are ignored");
    assert!(!blank.has_totp, "an empty totp string is no code");
}

#[test]
fn failures_are_classified_from_stderr() {
    assert_eq!(
        classify_failure("Vault is locked."),
        BwError::SessionExpired
    );
    assert_eq!(
        classify_failure("You are not logged in."),
        BwError::SessionExpired
    );
    assert!(matches!(
        classify_failure("Error: 503 Service Unavailable"),
        BwError::Server(_)
    ));
    assert!(matches!(
        classify_failure("fetch failed"),
        BwError::Server(_)
    ));
    assert!(matches!(
        classify_failure("Item not found."),
        BwError::Cli(_)
    ));
}

/// Tests that run a script take this lock so no thread forks while another holds the script open
/// for writing (ETXTBSY).
static SCRIPT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Sandbox {
    _tmp: tempfile::TempDir,
    bin_dir: PathBuf,
    data_dir: PathBuf,
}

fn sandbox() -> Sandbox {
    let tmp = tempfile::tempdir().unwrap();
    let bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    for f in [
        "fake_bw.sh",
        "list_items.json",
        "list_folders.json",
        "import_folder_items.json",
    ] {
        std::fs::copy(fixture_dir().join(f), bin_dir.join(f)).unwrap();
    }
    let data_dir = tmp.path().join("appdata");
    Sandbox {
        _tmp: tmp,
        bin_dir,
        data_dir,
    }
}

impl Sandbox {
    fn client(&self) -> CliClient {
        CliClient::new(self.bin_dir.join("fake_bw.sh"), self.data_dir.clone())
    }
    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.bin_dir.join(name)).unwrap_or_default()
    }
}

#[tokio::test]
async fn cli_client_logs_in_and_lists_through_the_binary() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    let out = c
        .login("sam@example.test", "correct horse", &Region::Eu, None)
        .await
        .unwrap();
    assert_eq!(out, LoginOutcome::Ok);

    let args = sb.log("args.log");
    assert!(
        args.contains("config server https://vault.bitwarden.eu --nointeraction"),
        "{args}"
    );
    assert!(
        args.contains("login sam@example.test --passwordenv=AUTHEXODUS_BW_PASSWORD --raw"),
        "{args}"
    );
    assert!(
        !args.contains("correct horse"),
        "the password is never an argument"
    );
    assert!(sb
        .log("env.log")
        .contains(&format!("appdata={}", sb.data_dir.display())));

    let logins = c.list_logins().await.unwrap();
    assert_eq!(logins.len(), 4);
    assert!(sb
        .log("env.log")
        .lines()
        .last()
        .unwrap()
        .contains("session=fake-session-key"));
    assert_eq!(
        c.import_folder_titles().await.unwrap(),
        vec!["Already Imported".to_string()]
    );
    c.sync().await.unwrap();
}

#[tokio::test]
async fn cli_client_tells_bad_credentials_from_two_factor() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    assert_eq!(
        c.login("sam@example.test", "wrong", &Region::Us, None)
            .await
            .unwrap(),
        LoginOutcome::BadCredentials
    );

    std::fs::write(sb.bin_dir.join("needs2fa"), "").unwrap();
    assert_eq!(
        c.login("sam@example.test", "correct horse", &Region::Us, None)
            .await
            .unwrap(),
        LoginOutcome::NeedsTwoFactor
    );
    assert_eq!(
        c.login(
            "sam@example.test",
            "correct horse",
            &Region::Us,
            Some("123456")
        )
        .await
        .unwrap(),
        LoginOutcome::Ok
    );
    let args = sb.log("args.log");
    assert!(args.contains("--method 0 --code 123456"), "{args}");
}

#[tokio::test]
async fn cli_client_reports_a_locked_vault_as_session_expiry() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    c.login("sam@example.test", "correct horse", &Region::Us, None)
        .await
        .unwrap();
    std::fs::write(sb.bin_dir.join("locked"), "").unwrap();
    assert_eq!(c.sync().await.unwrap_err(), BwError::SessionExpired);
}

#[tokio::test]
async fn logout_and_wipe_deletes_the_data_dir() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    c.login("sam@example.test", "correct horse", &Region::Us, None)
        .await
        .unwrap();
    std::fs::write(sb.data_dir.join("data.json"), "{}").unwrap();
    c.logout_and_wipe().await.unwrap();
    assert!(!sb.data_dir.exists());
    c.logout_and_wipe().await.unwrap(); // idempotent
}

#[tokio::test]
async fn cli_client_set_totp_edits_only_codeless_items_and_keeps_secrets_off_argv() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    c.login("sam@example.test", "correct horse", &Region::Us, None)
        .await
        .unwrap();
    let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";

    const ITEM: &str = "11111111-0000-4000-8000-000000000001";
    assert_eq!(c.set_totp(ITEM, uri).await.unwrap(), SetTotp::Attached);
    assert!(
        sb.log("encode.in").contains(uri),
        "item JSON with the new code went to `bw encode` on stdin"
    );
    assert_eq!(sb.log("edit.stdin").trim(), "ENCODEDJSON");
    assert!(
        !sb.log("args.log").contains("JBSWY3DPEHPK3PXP"),
        "the secret is never an argument"
    );

    std::fs::write(sb.bin_dir.join("item_has_code"), "").unwrap();
    std::fs::remove_file(sb.bin_dir.join("edit.stdin")).unwrap();
    assert_eq!(
        c.set_totp(ITEM, uri).await.unwrap(),
        SetTotp::AlreadyHasCode
    );
    assert!(
        !sb.bin_dir.join("edit.stdin").exists(),
        "no edit when a code exists"
    );

    // The login holds this very key already (written differently, under another label): an
    // earlier run did the work. Done, and still no edit.
    std::fs::write(sb.bin_dir.join("item_has_same_code"), "").unwrap();
    assert_eq!(c.set_totp(ITEM, uri).await.unwrap(), SetTotp::AlreadySet);
    assert!(!sb.bin_dir.join("edit.stdin").exists());
}

#[tokio::test]
async fn cli_client_creates_in_the_existing_import_folder() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    c.login("sam@example.test", "correct horse", &Region::Us, None)
        .await
        .unwrap();
    c.create_in_import_folder(
        "Quillpad (sam)",
        Some("sam@example.test"),
        "otpauth://totp/q?secret=JBSWY3DPEHPK3PXP",
    )
    .await
    .unwrap();
    let sent: serde_json::Value = serde_json::from_str(&sb.log("encode.in")).unwrap();
    assert_eq!(sent["type"], 1);
    assert_eq!(sent["name"], "Quillpad (sam)");
    assert_eq!(sent["folderId"], "22222222-0000-4000-8000-000000000002");
    assert_eq!(sent["login"]["username"], "sam@example.test");
    assert!(!sb.log("args.log").contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(sb.log("create.stdin").trim(), "ENCODEDJSON");
}

// ---------- fix round 1 ----------

#[test]
fn aws_token_does_not_attach_to_amazon_shopping() {
    let vault = vec![login(
        "shop",
        "Amazon",
        Some("sam@example.test"),
        &["www.amazon.ca"],
        false,
    )];
    let p = propose(
        &[tok(
            "t1",
            "Amazon Web Services",
            Some("Amazon Web Services"),
            Some("sam@example.test"),
        )],
        &vault,
    );
    assert_eq!(p[0].decision, Decision::CreateNew);
    assert!(p[0].candidates.is_empty());
}

#[test]
fn microsoft_token_does_not_attach_to_live_nation_or_office_depot() {
    let vault = vec![
        login("ln", "Live Nation", None, &["livenation.com"], false),
        login("od", "Office Depot", None, &["officedepot.com"], false),
    ];
    let p = propose(&[tok("t1", "Microsoft", Some("Microsoft"), None)], &vault);
    assert_eq!(p[0].decision, Decision::CreateNew);
    assert_eq!(p[0].confidence, Confidence::High);
}

#[test]
fn a_match_resting_only_on_an_alias_is_low() {
    let vault = vec![
        login(
            "aws",
            "Cloud console",
            None,
            &["console.aws.amazon.com"],
            false,
        ),
        login("ms", "Outlook", None, &["login.live.com"], false),
    ];
    let p = propose(
        &[
            tok(
                "a",
                "Amazon Web Services",
                Some("Amazon Web Services"),
                None,
            ),
            tok("m", "Microsoft", Some("Microsoft"), None),
        ],
        &vault,
    );
    assert_eq!(p[0].decision, attach("aws"));
    assert_eq!(p[0].confidence, Confidence::Low);
    assert_eq!(p[1].decision, attach("ms"));
    assert_eq!(p[1].confidence, Confidence::Low);
    // The token's own name is still High.
    let own = propose(
        &[tok("m", "Microsoft", Some("Microsoft"), None)],
        &[login("ms", "Microsoft account", None, &[], false)],
    );
    assert_eq!(own[0].confidence, Confidence::High);
}

#[test]
fn keys_match_whole_words_and_labels_never_substrings() {
    let vault = vec![
        login("a", "Orchard", None, &["pineapple.com"], false),
        login("b", "Chat", None, &["blackslackline.com"], false),
    ];
    for name in ["Apple", "Slack"] {
        let p = propose(&[tok("t", name, Some(name), None)], &vault);
        assert_eq!(p[0].decision, Decision::CreateNew, "{name}");
        assert!(p[0].candidates.is_empty(), "{name}");
    }
    // Real hits still work: a whole label, and a multi-word name squashed into one label.
    let vault = vec![
        login("so", "Q&A", None, &["stackoverflow.com"], false),
        login("ap", "iCloud", None, &["appleid.apple.com"], false),
    ];
    let p = propose(
        &[
            tok("1", "Stack Overflow", Some("Stack Overflow"), None),
            tok("2", "Apple", Some("Apple"), None),
        ],
        &vault,
    );
    assert_eq!(p[0].decision, attach("so"));
    assert_eq!(p[1].decision, attach("ap"));
}

#[test]
fn only_real_server_errors_are_server_errors() {
    assert!(matches!(classify_failure("Error: 503"), BwError::Server(_)));
    assert!(matches!(
        classify_failure("Request failed with status code 502"),
        BwError::Server(_)
    ));
    assert!(matches!(classify_failure("HTTP 500"), BwError::Server(_)));
    assert!(matches!(
        classify_failure("Item \"Network 500 backup\" not found."),
        BwError::Cli(_)
    ));
    assert!(matches!(
        classify_failure("Not found: id 15034"),
        BwError::Cli(_)
    ));
    assert!(matches!(
        classify_failure("Unknown network card"),
        BwError::Cli(_)
    ));
}

#[tokio::test]
async fn parent_bitwarden_environment_does_not_reach_the_child() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let vars = [
        ("BW_SESSION", "parent-session"),
        ("BW_PASSWORD", "parent-pw"),
        ("BW_CLIENTID", "parent-id"),
        ("BW_CLIENTSECRET", "parent-secret"),
        ("BW_RESPONSE", "true"),
        ("BITWARDENCLI_APPDATA_DIR", "/somewhere/else"),
        // Where the master password would go, and whether its TLS would be checked.
        ("HTTPS_PROXY", "http://parent-proxy.invalid:3128"),
        ("https_proxy", "http://parent-proxy.invalid:3128"),
        ("HTTP_PROXY", "http://parent-proxy.invalid:3128"),
        ("ALL_PROXY", "socks5://parent-proxy.invalid:1080"),
        ("NO_PROXY", "parent-noproxy.invalid"),
        ("NODE_EXTRA_CA_CERTS", "/parent/extra-ca.pem"),
        ("NODE_TLS_REJECT_UNAUTHORIZED", "0"),
        ("NODE_OPTIONS", "--require=/parent/hook.js"),
        ("SSL_CERT_FILE", "/parent/certs.pem"),
        // What code the child would load.
        ("DYLD_INSERT_LIBRARIES", "/parent/inject.dylib"),
        ("DYLD_LIBRARY_PATH", "/parent/lib"),
        ("LD_PRELOAD", "/parent/inject.so"),
        // And anything else at all.
        ("AUTHEXODUS_TEST_UNRELATED", "parent-unrelated"),
    ];
    // SAFETY: every test that reads the environment runs a script under SCRIPT_LOCK, held here.
    for (k, v) in vars {
        unsafe { std::env::set_var(k, v) };
    }
    let mut c = sb.client();
    let r = c
        .login("sam@example.test", "correct horse", &Region::Us, None)
        .await;
    c.sync().await.unwrap();
    for (k, _) in vars {
        unsafe { std::env::remove_var(k) };
    }
    assert_eq!(r.unwrap(), LoginOutcome::Ok);
    let env = sb.log("env.log");
    assert!(!env.contains("parent-"), "{env}");
    assert!(!env.contains("resp=true"), "{env}");
    assert!(!env.contains("/somewhere/else"), "{env}");
    assert!(env.contains(&format!("appdata={}", sb.data_dir.display())));

    // The whole environment of every run of the child, as `env` printed it.
    let full = sb.log("env.full");
    assert!(full.contains("BW_NOINTERACTION=true"), "{full}");
    for (name, value) in vars {
        if name == "BITWARDENCLI_APPDATA_DIR" || name == "BW_SESSION" {
            // The app sets these itself; the parent's value must not be the one used.
            assert!(
                !full.contains(value),
                "{name} came from the parent:\n{full}"
            );
        } else {
            assert!(
                !full.lines().any(|l| l.starts_with(&format!("{name}="))),
                "{name} reached the child:\n{full}"
            );
        }
    }
    assert!(!full.contains("parent"), "{full}");
    // What it does get: a fixed PATH, the app's settings, and a short list from the parent.
    assert!(
        full.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin\n"),
        "{full}"
    );
    let allowed = [
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "BW_NOINTERACTION",
        "BITWARDENCLI_APPDATA_DIR",
        "BW_SESSION",
        "AUTHEXODUS_BW_PASSWORD",
        // set by the shell that runs the stand-in script, not by the app
        "PWD",
        "SHLVL",
        "OLDPWD",
        "_",
        "__CF_USER_TEXT_ENCODING",
    ];
    for line in full.lines() {
        let name = line.split('=').next().unwrap();
        assert!(
            allowed.contains(&name),
            "unexpected {name} in the child:\n{full}"
        );
    }
}

#[tokio::test]
async fn two_tokens_with_one_title_make_two_logins_and_rerun_adds_nothing() {
    let fake = FakeBw::new(vec![]);
    let mut a = tok("a", "Admin", Some("Shop"), None);
    let mut b = tok("b", "Admin", Some("Shop"), None);
    a.title = "Shop (Admin)".into();
    b.title = "Shop (Admin)".into();
    // Two accounts that happen to share a name: each has its own key.
    b.secret = Secret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    let tokens = [a, b];
    let decisions = vec![
        ("a".to_string(), Decision::CreateNew),
        ("b".to_string(), Decision::CreateNew),
    ];
    let r = apply(&fake, &tokens, &decisions, &no_progress()).await;
    assert_eq!((r.created, r.skipped, r.failed.clone()), (2, 0, None));
    assert_eq!(
        fake.titles(),
        vec!["Shop (Admin)".to_string(), "Shop (Admin) (2)".to_string()]
    );
    let again = apply(&fake, &tokens, &decisions, &no_progress()).await;
    assert_eq!((again.created, again.skipped), (0, 0));
    assert_eq!(again.kept.len(), 2, "{:?}", again.kept);
    assert_eq!(fake.titles().len(), 2);
}

#[tokio::test]
async fn truncated_download_leaves_no_part_file() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\nshort",
            )
            .await;
        let _ = sock.shutdown().await;
    });
    let dir = tempfile::tempdir().unwrap();
    let err = ensure_cli_from(
        dir.path(),
        &format!("http://127.0.0.1:{port}"),
        "bw-test.zip",
        &sha256_hex(b"x"),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, BwError::Download(_)), "{err:?}");
    assert!(!dir.path().join("bw-test.zip.part").exists());
}

// ---------- fix round 2 ----------

#[test]
fn a_key_in_a_subdomain_label_never_gives_high_confidence() {
    for host in [
        "apple.com.evil.example",
        "apple.evil.com",
        "github.evil.org",
    ] {
        let key = host.split('.').next().unwrap();
        let name = if key == "apple" { "Apple" } else { "GitHub" };
        let vault = vec![login("x", "Some site", None, &[host], false)];
        let p = propose(&[tok("t", name, Some(name), None)], &vault);
        assert!(
            !(matches!(p[0].decision, Decision::Attach { .. })
                && p[0].confidence == Confidence::High),
            "{host}: {:?}",
            p[0]
        );
    }
}

#[test]
fn registrable_label_still_matches_with_subdomains_and_country_suffixes() {
    let vault = vec![
        login("ap", "Account", None, &["id.apple.com"], false),
        login("am", "Shopping", None, &["www.amazon.co.uk"], false),
    ];
    let p = propose(
        &[
            tok("1", "Apple", Some("Apple"), None),
            tok("2", "Amazon", Some("Amazon"), None),
        ],
        &vault,
    );
    assert_eq!(
        (p[0].decision.clone(), p[0].confidence),
        (attach("ap"), Confidence::High)
    );
    assert_eq!(
        (p[1].decision.clone(), p[1].confidence),
        (attach("am"), Confidence::High)
    );
}

#[test]
fn url_furniture_in_a_login_name_is_not_matchable() {
    let vault = vec![login(
        "u",
        "https://www.example.com/login",
        None,
        &[],
        false,
    )];
    for key in ["Com", "Https", "Www"] {
        let p = propose(&[tok("t", key, Some(key), None)], &vault);
        assert_eq!(p[0].decision, Decision::CreateNew, "{key}");
        assert!(p[0].candidates.is_empty(), "{key}");
    }
    // The registrable label of a URL-shaped name still counts.
    let p = propose(&[tok("t", "Example", Some("Example"), None)], &vault);
    assert_eq!(p[0].decision, attach("u"));
    assert_eq!(p[0].confidence, Confidence::High);
}

#[test]
fn ip_address_hosts_never_match_a_key() {
    let vault = vec![login(
        "r",
        "Router",
        None,
        &["192.168.0.1", "10.0.0.1", "[::1]"],
        false,
    )];
    for key in ["Router2", "Admin", "192"] {
        let p = propose(&[tok("t", key, Some(key), None)], &vault);
        assert_eq!(p[0].decision, Decision::CreateNew, "{key}");
    }
}

// ---------- final review ----------

/// Tokens with secrets of their own (the shared builder gives every token the same one).
fn distinct(tokens: Vec<Token>) -> Vec<Token> {
    const SECRETS: &[&str] = &[
        "JBSWY3DPEHPK3PXP",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U",
        "ON4W45DIMV2GSYZAORSXG5BANNSXSIBU",
        "KRUGS4ZANFZSAYJAON4W45DIMV2GSYZA",
        "MZXW6YTBOJRGC6RAON4W45DIMV2GSYZA",
        "NBSWY3DPEB3W64TMMQQGM33SEB2GK43U",
        "OBQXG43XN5ZGIIDGN5ZCA5DFON2HGIDP",
        "ONSWG4TFOQQGM33SEB2GK43UOMQG63TM",
        "ORSXG5BAONSWG4TFOQQG4ZLWMVZCA4TF",
        "MFWCAIDGN5ZCA5DFON2HGIDPNZWHSIDP",
        "NZWHSIDGN5ZCA5DFON2HGIDBNZSCA3TP",
    ];
    assert!(tokens.len() <= SECRETS.len());
    tokens
        .into_iter()
        .zip(SECRETS)
        .map(|(mut t, secret)| {
            t.secret = Secret::new((*secret).into());
            t
        })
        .collect()
}

#[tokio::test]
async fn a_rerun_reports_its_own_attaches_as_done_not_as_codes_that_were_already_there() {
    let (tokens, vault, decisions) = twelve();
    let fake = FakeBw::new(vault);
    let first = apply(&fake, &tokens, &decisions, &no_progress()).await;
    assert_eq!((first.attached, first.created, first.failed), (6, 6, None));
    assert!(first.kept.is_empty());

    let writes = fake.writes();
    let lines = Mutex::new(Vec::new());
    let second = apply(&fake, &tokens, &decisions, &|line| {
        lines.lock().unwrap().push(line)
    })
    .await;
    assert_eq!(second.failed, None);
    assert_eq!(fake.writes(), writes, "nothing is written twice");
    assert_eq!(second.attached, 6, "the codes this app attached are done");
    assert_eq!((second.created, second.skipped), (0, 0));
    assert_eq!(
        second.kept,
        (6..12)
            .map(|i| kept_same_title(&format!("Svc{i}")))
            .collect::<Vec<_>>(),
        "the logins the first run made are reported as already in Bitwarden, not as skipped"
    );
    let lines = lines.into_inner().unwrap();
    assert!(
        lines.iter().any(|l| l == "Svc0 already has this code"),
        "{lines:?}"
    );
    for line in &lines {
        for token in &tokens {
            assert!(
                !line.contains(token.secret.expose()),
                "a secret in {line:?}"
            );
        }
    }

    // A login that holds a different code is still left alone, and counted as skipped.
    let other = FakeBw::new(vec![login("L0", "Svc0", None, &[], false)]);
    let earlier = tok("x", "Svc0", None, None); // the shared builder's secret
    apply(
        &other,
        std::slice::from_ref(&earlier),
        &[("x".to_string(), attach("L0"))],
        &no_progress(),
    )
    .await;
    let mine = &tokens[1]; // a different secret
    let r = apply(
        &other,
        std::slice::from_ref(mine),
        &[(mine.id.clone(), attach("L0"))],
        &no_progress(),
    )
    .await;
    assert_eq!((r.attached, r.skipped, r.kept.len()), (0, 1, 0));
    assert!(other.totp_of("L0").unwrap().contains("JBSWY3DPEHPK3PXP"));
}

#[test]
fn a_token_whose_only_matches_already_hold_a_code_is_a_question() {
    let vault = vec![
        login(
            "gh",
            "GitHub",
            Some("sam@example.test"),
            &["github.com"],
            true,
        ),
        login("gh2", "GitHub (work)", None, &["github.com"], true),
        login("x", "Unrelated", None, &["example.test"], false),
    ];
    let p = propose(
        &[tok(
            "t1",
            "GitHub",
            Some("GitHub"),
            Some("sam@example.test"),
        )],
        &vault,
    );
    assert_eq!(p[0].decision, Decision::CreateNew);
    assert_eq!(
        p[0].confidence,
        Confidence::Low,
        "creating a second GitHub login is not to be decided silently"
    );
    assert_eq!(p[0].candidates, ["gh", "gh2"], "the person sees why");
}

#[tokio::test]
async fn apply_half_sign_in_again_propose_apply_makes_no_duplicates() {
    for persisted in [false, true] {
        // Twelve tokens: six match a login by name, six match nothing.
        let (tokens, vault, _) = twelve();
        let fake = FakeBw::new(vault);
        let decide = |fake: &FakeBw| -> Vec<(String, Decision)> {
            let vault = fake.0.lock().unwrap().logins.clone();
            propose(&tokens, &vault)
                .into_iter()
                .map(|p| (p.token_id, p.decision))
                .collect()
        };

        // The first run stops part of the way through the attaches.
        let first_decisions = decide(&fake);
        fake.0.lock().unwrap().fail = Some((
            4,
            BwError::Server("503 Service Unavailable".into()),
            persisted,
        ));
        let first = apply(&fake, &tokens, &first_decisions, &no_progress()).await;
        assert!(first.failed.is_some());
        assert_eq!(first.attached, 3);

        // The person signs in again and is shown fresh proposals, and accepts them as they
        // are: the worst case, in which nobody notices anything.
        fake.clear_failure();
        let second_decisions = decide(&fake);
        let second = apply(&fake, &tokens, &second_decisions, &no_progress()).await;
        assert_eq!(second.failed, None);
        // And once more for good measure.
        let third_decisions = decide(&fake);
        let third = apply(&fake, &tokens, &third_decisions, &no_progress()).await;
        assert_eq!((third.failed, third.created), (None, 0));

        // Every token's code is in the vault exactly once.
        let state = fake.0.lock().unwrap();
        for token in &tokens {
            let holders = state
                .totp_values
                .values()
                .chain(state.created_codes.iter())
                .filter(|value| value.contains(&format!("secret={}", token.secret.expose())))
                .count();
            assert_eq!(
                holders, 1,
                "{} is in the vault {holders} times (server kept the failed write: {persisted})",
                token.title
            );
        }
        assert_eq!(state.folder_titles.len(), 6, "{:?}", state.folder_titles);
        assert_eq!(state.totp_values.len(), 6);
    }
}

#[tokio::test]
async fn two_step_outcomes_follow_what_the_tool_says_and_whether_a_code_was_sent() {
    let _g = SCRIPT_LOCK.lock().await;
    let try_login = |flag: &'static str, code: Option<&'static str>| async move {
        let sb = sandbox();
        std::fs::write(sb.bin_dir.join(flag), "").unwrap();
        let mut c = sb.client();
        c.login("sam@example.test", "correct horse", &Region::Us, code)
            .await
    };

    // No code yet: Bitwarden wants one.
    assert_eq!(
        try_login("needs2fa", None).await,
        Ok(LoginOutcome::NeedsTwoFactor)
    );
    // Several two-step methods and none chosen: the app's next try names the authenticator app.
    assert_eq!(
        try_login("manymethods", None).await,
        Ok(LoginOutcome::NeedsTwoFactor)
    );
    assert_eq!(
        try_login("manymethods", Some("123456")).await,
        Ok(LoginOutcome::Ok)
    );

    // A code was sent and refused: never "needs a code" again.
    assert_eq!(
        try_login("wrong2fa", Some("000000")).await,
        Ok(LoginOutcome::BadTwoFactorCode)
    );
    assert_eq!(
        try_login("askedagain", Some("000000")).await,
        Ok(LoginOutcome::BadTwoFactorCode)
    );

    // An account with no two-step login, on a device Bitwarden has not seen (this app's
    // private data folder always is one), is asked for the code Bitwarden emails. Without a
    // code sent, the tool's words are the same as for an authenticator-app account, so the
    // first answer can only be "a code is needed"; the UI offers the API key beside the code
    // field for exactly this case.
    assert_eq!(
        try_login("devicecheck", None).await,
        Ok(LoginOutcome::NeedsTwoFactor)
    );
    // What a password sign-in cannot get past is its own answer, so the person can be sent
    // to sign in with an API key: never a failure to connect, never "needs a code" again.
    assert_eq!(
        try_login("devicecheck", Some("123456")).await,
        Ok(LoginOutcome::NeedsApiKey),
        "a code was sent and the tool still asks for one: it is the emailed code it wants"
    );
    assert_eq!(
        try_login("noauthapp", Some("123456")).await,
        Ok(LoginOutcome::NeedsApiKey)
    );
    assert_eq!(
        try_login("noproviders", None).await,
        Ok(LoginOutcome::NeedsApiKey)
    );
    assert_eq!(
        try_login("noproviders", Some("123456")).await,
        Ok(LoginOutcome::NeedsApiKey)
    );

    // The wrong master password is still that, code or no code.
    let sb = sandbox();
    std::fs::write(sb.bin_dir.join("wrong2fa"), "").unwrap();
    let mut c = sb.client();
    assert_eq!(
        c.login("sam@example.test", "wrong", &Region::Us, Some("123456"))
            .await,
        Ok(LoginOutcome::BadCredentials)
    );
}

#[test]
fn sign_in_input_is_checked_before_it_can_reach_the_tool() {
    let ok = |email: &str, region: Region| check_login_input(email, &region);
    assert_eq!(ok("sam@example.test", Region::Us), Ok(()));
    assert_eq!(ok("sam+tag@example.test", Region::Eu), Ok(()));
    for good in [
        "https://vault.example.test",
        "  https://vault.example.test/  ",
        "https://vault.example.test:8443/bitwarden",
        "https://192.0.2.10",
        "HTTPS://Vault.Example.Test",
    ] {
        assert_eq!(
            ok("sam@example.test", Region::SelfHosted(good.into())),
            Ok(()),
            "{good}"
        );
    }
    for bad in [
        "",
        "   ",
        "vault.example.test",
        "http://vault.example.test",
        "ftp://vault.example.test",
        "https://",
        "https://sam:hunter2@vault.example.test",
        "https://sam@vault.example.test",
        "--help",
        "--server=https://evil.example.test",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ] {
        assert_eq!(
            ok("sam@example.test", Region::SelfHosted(bad.into())),
            Err(BwError::BadServerUrl),
            "{bad:?}"
        );
    }
    for bad in [
        "",
        "sam",
        "@example.test",
        "sam@",
        "-sam@example.test",
        "--passwordenv=HOME@x",
        "sam @example.test",
        "sam@example.test\n--raw",
    ] {
        assert_eq!(ok(bad, Region::Us), Err(BwError::BadEmail), "{bad:?}");
    }
    // What goes to `bw config server` is the address as parsed, without the padding.
    assert_eq!(
        Region::SelfHosted("  https://Vault.Example.Test/  ".into()).server_url(),
        "https://vault.example.test"
    );
    assert_eq!(
        Region::SelfHosted("https://vault.example.test:8443/bitwarden/".into()).server_url(),
        "https://vault.example.test:8443/bitwarden"
    );

    assert!(is_vault_id("11111111-0000-4000-8000-000000000001"));
    assert!(is_vault_id("ABCDEF12-abcd-4ABC-8abc-abcdefABCDEF"));
    for bad in [
        "",
        "--help",
        "item-1",
        "11111111-0000-4000-8000-00000000000",
        "11111111-0000-4000-8000-0000000000011",
        "11111111_0000_4000_8000_000000000001",
        "1111111g-0000-4000-8000-000000000001",
        "-1111111-0000-4000-8000-000000000001",
    ] {
        assert!(!is_vault_id(bad), "{bad:?}");
    }
}

#[tokio::test]
async fn the_client_refuses_bad_input_and_odd_ids_without_running_the_tool_on_them() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    assert_eq!(
        c.login(
            "sam@example.test",
            "correct horse",
            &Region::SelfHosted("http://vault.example.test".into()),
            None
        )
        .await,
        Err(BwError::BadServerUrl)
    );
    assert_eq!(
        c.login("--raw", "correct horse", &Region::Us, None).await,
        Err(BwError::BadEmail)
    );
    assert_eq!(sb.log("args.log"), "", "the tool was never started");
    assert!(!sb.data_dir.exists());

    c.login("sam@example.test", "correct horse", &Region::Us, None)
        .await
        .unwrap();
    let before = sb.log("args.log");
    let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
    for odd in [
        "--help",
        "item-1",
        "",
        "11111111-0000-4000-8000-000000000001 --pretty",
    ] {
        assert!(
            matches!(c.set_totp(odd, uri).await, Err(BwError::Cli(_))),
            "{odd:?}"
        );
    }
    assert_eq!(sb.log("args.log"), before, "no run was made with an odd id");

    // A folder id of the wrong shape, as a hostile server could send, is not used either:
    // neither one that is listed, nor one handed back when the folder is created.
    std::fs::write(sb.bin_dir.join("odd_folder_id"), "").unwrap();
    assert!(matches!(
        c.import_folder_titles().await,
        Err(BwError::Cli(_))
    ));
    assert!(matches!(
        c.create_in_import_folder("T", None, uri).await,
        Err(BwError::Cli(_))
    ));
    std::fs::remove_file(sb.bin_dir.join("odd_folder_id")).unwrap();
    std::fs::write(sb.bin_dir.join("no_import_folder"), "").unwrap();
    std::fs::write(sb.bin_dir.join("odd_new_id"), "").unwrap();
    assert!(matches!(
        c.create_in_import_folder("T", None, uri).await,
        Err(BwError::Cli(_))
    ));
    let args = sb.log("args.log");
    assert!(
        !args.contains("--pretty") && !args.contains("--organizationid"),
        "{args}"
    );
    assert!(!args.contains("create item"), "no item was created: {args}");
}

#[tokio::test]
async fn a_swapped_binary_is_not_run() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let script = sb.bin_dir.join("fake_bw.sh");
    let recorded = sha256_hex(&std::fs::read(&script).unwrap());
    let mut c = sb.client().expecting_sha256(recorded.to_uppercase());
    assert_eq!(
        c.login("sam@example.test", "correct horse", &Region::Us, None)
            .await,
        Ok(LoginOutcome::Ok)
    );

    // Something replaces the program after it was extracted and before the next sign-in.
    let mut swapped = std::fs::read(&script).unwrap();
    swapped.extend_from_slice(b"\n# swapped\n");
    std::fs::write(&script, swapped).unwrap();
    let before = sb.log("args.log");
    let mut c = sb.client().expecting_sha256(recorded);
    assert_eq!(
        c.login("sam@example.test", "correct horse", &Region::Us, None)
            .await,
        Err(BwError::ChecksumMismatch)
    );
    assert_eq!(
        sb.log("args.log"),
        before,
        "the swapped program was not run"
    );
}

#[tokio::test]
async fn an_oversized_download_is_abandoned_and_planted_links_are_not_followed() {
    let zip = bw_zip(b"#!/bin/sh\necho pretend bw\n");
    let expected = sha256_hex(&zip);
    let base = file_server(zip.clone()).await;

    // Larger than allowed: refused, nothing kept.
    let dir = tempfile::tempdir().unwrap();
    let err = ensure_cli_within(
        dir.path(),
        &base,
        "bw-test.zip",
        &expected,
        zip.len() as u64 - 1,
        &|_| {},
        &Cancel::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, BwError::Download(m) if m.contains("larger than expected")),
        "{err:?}"
    );
    assert!(!dir.path().join("bw-test.zip.part").exists());
    assert!(!dir.path().join("bw-test.zip").exists());
    assert!(!dir.path().join("bw").exists());

    // Exactly the allowed size is fine, and the folder is the owner's alone.
    ensure_cli_within(
        dir.path(),
        &base,
        "bw-test.zip",
        &expected,
        zip.len() as u64,
        &|_| {},
        &Cancel::new(),
    )
    .await
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // Links planted where the temporary files go are replaced, never written through.
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("bw-test.zip.part")).unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("bw.partial")).unwrap();
        let got = ensure_cli_from(dir.path(), &base, "bw-test.zip", &expected)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&got.path)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[test]
fn a_code_mark_is_the_same_for_one_key_however_it_is_written_and_prints_nothing() {
    let mark = CodeMark::of_secret("JBSWY3DPEHPK3PXP").unwrap();
    for same in [
        "jbswy3dpehpk3pxp",
        "JBSW Y3DP EHPK 3PXP",
        "JBSW-Y3DP-EHPK-3PXP",
        "JBSWY3DPEHPK3PXP====",
    ] {
        assert_eq!(CodeMark::of_secret(same), Some(mark), "{same}");
        assert_eq!(CodeMark::of_totp_field(same), Some(mark), "{same}");
    }
    for uri in [
        "otpauth://totp/Example:sam?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30",
        "otpauth://totp/x?issuer=Other&SECRET=jbswy3dpehpk3pxp",
        "  OTPAUTH://totp/x?secret=JBSW%20Y3DP%20EHPK%203PXP  ",
    ] {
        assert_eq!(CodeMark::of_totp_field(uri), Some(mark), "{uri}");
    }
    assert_ne!(
        CodeMark::of_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        Some(mark)
    );
    for none in [
        "",
        "   ",
        "otpauth://totp/x?issuer=NoSecret",
        "not base32 at all!",
        "steam://ABC",
    ] {
        assert_eq!(CodeMark::of_totp_field(none), None, "{none:?}");
    }
    let printed = format!("{mark:?} {:?}", login("a", "A", None, &[], true));
    assert!(printed.contains("CodeMark(..)"), "{printed}");
    assert!(!printed.contains("JBSW"), "{printed}");

    // The list of logins carries the mark, never the key.
    let logins = parse_login_items(&fixture("list_items.json")).unwrap();
    assert_eq!(logins[0].code, Some(mark));
    assert_eq!(logins[1].code, None);
    assert!(!format!("{logins:?}").contains("JBSWY3DPEHPK3PXP"));
}

#[tokio::test]
async fn a_token_whose_code_is_already_in_the_vault_is_not_given_a_second_login() {
    // The person moved this account by hand some time ago, to a login the matcher would
    // never connect with it.
    let mut held = login("x", "Something else entirely", None, &[], true);
    held.code = CodeMark::of_secret("JBSWY3DPEHPK3PXP");
    let fake = FakeBw::new(vec![held]);
    let tokens = [tok("t", "Quillpad", None, None)];
    let lines = Mutex::new(Vec::new());
    let r = apply(
        &fake,
        &tokens,
        &[("t".to_string(), Decision::CreateNew)],
        &|line| lines.lock().unwrap().push(line),
    )
    .await;
    assert_eq!((r.created, r.skipped, r.failed), (0, 0, None));
    assert_eq!(r.kept, vec![kept_same_code("Quillpad")]);
    assert_eq!(fake.writes(), 0);
    assert!(lines
        .into_inner()
        .unwrap()
        .contains(&"Quillpad already has this code in Bitwarden".to_string()));

    // Two tokens that carry one and the same key (the account was added to Authy twice)
    // make one login, not two.
    let fake = FakeBw::new(vec![]);
    let twins = [
        tok("a", "Twin A", None, None),
        tok("b", "Twin B", None, None),
    ];
    let decisions = vec![
        ("a".to_string(), Decision::CreateNew),
        ("b".to_string(), Decision::CreateNew),
    ];
    let r = apply(&fake, &twins, &decisions, &no_progress()).await;
    assert_eq!((r.created, r.skipped), (1, 0));
    assert_eq!(r.kept, vec![kept_same_code("Twin B")]);
}

// ---------- completeness fixes ----------

const API_CLIENT_ID: &str = "user.11111111-0000-4000-8000-000000000001";
const API_CLIENT_SECRET: &str = "synthetic0secret0value";

#[tokio::test]
async fn an_api_key_reaches_one_child_only_and_the_password_only_the_unlock() {
    let _g = SCRIPT_LOCK.lock().await;
    let sb = sandbox();
    let mut c = sb.client();
    let out = c
        .login_with_api_key(
            &format!("  {API_CLIENT_ID} "),
            API_CLIENT_SECRET,
            "correct horse",
            &Region::Eu,
        )
        .await
        .unwrap();
    assert_eq!(out, LoginOutcome::Ok);
    c.sync().await.unwrap();
    assert_eq!(c.list_logins().await.unwrap().len(), 4);

    let args = sb.log("args.log");
    let env = sb.log("env.log");
    assert!(
        !args.contains(API_CLIENT_ID),
        "the key is never an argument"
    );
    assert!(!args.contains(API_CLIENT_SECRET), "{args}");
    assert!(!args.contains("correct horse"), "{args}");
    let runs: Vec<(&str, &str)> = args.lines().zip(env.lines()).collect();
    assert_eq!(args.lines().count(), env.lines().count());
    let words: Vec<&str> = runs
        .iter()
        .map(|(args, _)| args.split(' ').next().unwrap())
        .collect();
    assert_eq!(
        words,
        ["logout", "config", "login", "unlock", "sync", "list"],
        "{args}"
    );
    for (args, env) in &runs {
        let has_key = env.contains(&format!("cid={API_CLIENT_ID} sec={API_CLIENT_SECRET}"));
        let has_password = env.contains("mine=correct horse");
        match args.split(' ').next().unwrap() {
            "login" => {
                assert_eq!(*args, "login --apikey --nointeraction");
                assert!(has_key, "{env}");
                assert!(
                    !has_password,
                    "the sign-in does not need the password: {env}"
                );
            }
            "unlock" => {
                assert!(
                    args.starts_with("unlock --passwordenv=AUTHEXODUS_BW_PASSWORD --raw"),
                    "{args}"
                );
                assert!(has_password, "{env}");
                assert!(env.contains("cid=none sec=none"), "{env}");
            }
            _ => {
                assert!(env.contains("cid=none sec=none"), "{args}: {env}");
                assert!(env.contains("mine=none"), "{args}: {env}");
            }
        }
    }
    // The session key comes from the unlock and is what later runs are given.
    assert!(env
        .lines()
        .last()
        .unwrap()
        .contains("session=fake-session-key"));

    // A key Bitwarden refuses, a key that is not shaped like one, and a wrong master
    // password are all "the details are wrong", not failures to connect.
    let sb = sandbox();
    let mut c = sb.client();
    assert_eq!(
        c.login_with_api_key(
            API_CLIENT_ID,
            "another0secret0value00",
            "correct horse",
            &Region::Us
        )
        .await,
        Ok(LoginOutcome::BadCredentials)
    );
    assert_eq!(
        c.login_with_api_key(API_CLIENT_ID, API_CLIENT_SECRET, "wrong", &Region::Us)
            .await,
        Ok(LoginOutcome::BadCredentials)
    );
    let runs_before = sb.log("args.log").lines().count();
    for (id, secret) in [
        ("", API_CLIENT_SECRET),
        ("11111111-0000-4000-8000-000000000001", API_CLIENT_SECRET),
        (
            "organization.11111111-0000-4000-8000-000000000001",
            API_CLIENT_SECRET,
        ),
        ("user.not-an-id", API_CLIENT_SECRET),
        (API_CLIENT_ID, ""),
        (API_CLIENT_ID, "has a space in it"),
        (API_CLIENT_ID, "--raw"),
    ] {
        assert_eq!(
            c.login_with_api_key(id, secret, "correct horse", &Region::Us)
                .await,
            Ok(LoginOutcome::BadCredentials),
            "{id:?} {secret:?}"
        );
    }
    assert_eq!(
        sb.log("args.log").lines().count(),
        runs_before,
        "the tool is not run for a key that is not shaped like one"
    );
    // The server address is checked for this kind of sign-in too.
    assert_eq!(
        c.login_with_api_key(
            API_CLIENT_ID,
            API_CLIENT_SECRET,
            "correct horse",
            &Region::SelfHosted("http://vault.example.test".into())
        )
        .await,
        Err(BwError::BadServerUrl)
    );
}

/// A megabyte and a half that is not one byte repeated, inside a zip that holds `bw`.
fn big_bw_zip() -> Vec<u8> {
    let program: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    bw_zip(&program)
}

#[tokio::test]
async fn preparing_the_tool_says_how_far_it_is() {
    let zip = big_bw_zip();
    let expected = sha256_hex(&zip);
    let size = zip.len() as u64;
    let base = file_server(zip).await;
    let dir = tempfile::tempdir().unwrap();
    let stages = Mutex::new(Vec::new());
    let note = |stage: PrepareStage| stages.lock().unwrap().push(stage);

    ensure_cli_within(
        dir.path(),
        &base,
        "bw-test.zip",
        &expected,
        10 * 1024 * 1024,
        &note,
        &Cancel::new(),
    )
    .await
    .unwrap();
    let first = std::mem::take(&mut *stages.lock().unwrap());
    assert_eq!(
        first.first(),
        Some(&PrepareStage::Downloading {
            received: 0,
            total: Some(size)
        })
    );
    let megabytes: Vec<u64> = first
        .iter()
        .filter_map(|stage| match stage {
            PrepareStage::Downloading { received, total } => {
                assert_eq!(*total, Some(size));
                Some(received / (1024 * 1024))
            }
            _ => None,
        })
        .collect();
    assert_eq!(megabytes, [0, 1], "once at the start, then once a megabyte");
    assert_eq!(
        first[first.len() - 2..],
        [PrepareStage::Checking, PrepareStage::Ready]
    );

    // With the verified download kept from before, there is nothing to download.
    ensure_cli_within(
        dir.path(),
        "http://127.0.0.1:1",
        "bw-test.zip",
        &expected,
        10 * 1024 * 1024,
        &note,
        &Cancel::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        *stages.lock().unwrap(),
        [PrepareStage::Checking, PrepareStage::Ready]
    );
}

#[tokio::test]
async fn a_stopped_download_leaves_no_partial_file() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // A server that sends a megabyte and a half of three, then goes quiet with the
    // connection open: the download can only end by being stopped.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3145728\r\n\r\n")
            .await;
        let _ = sock.write_all(&vec![7u8; 1_572_864]).await;
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    });
    let dir = tempfile::tempdir().unwrap();
    let cancel = Cancel::new();
    let stop_at_a_megabyte = |stage: PrepareStage| {
        if matches!(stage, PrepareStage::Downloading { received, .. } if received >= 1024 * 1024) {
            cancel.cancel();
        }
    };
    let stopped = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        ensure_cli_within(
            dir.path(),
            &format!("http://127.0.0.1:{port}"),
            "bw-test.zip",
            &sha256_hex(b"x"),
            10 * 1024 * 1024,
            &stop_at_a_megabyte,
            &cancel,
        ),
    )
    .await
    .expect("a stopped download returns at once");
    assert_eq!(stopped.unwrap_err(), BwError::Cancelled);
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "left behind: {left:?}");

    // Stopped before it began: nothing is fetched, nothing is made.
    let dir = tempfile::tempdir().unwrap();
    let zip = bw_zip(b"#!/bin/sh\necho pretend bw\n");
    let expected = sha256_hex(&zip);
    let base = file_server(zip.clone()).await;
    let cancel = Cancel::new();
    cancel.cancel();
    let stopped = ensure_cli_within(
        dir.path().join("bw-cli").as_path(),
        &base,
        "bw-test.zip",
        &expected,
        1024 * 1024,
        &|_| {},
        &cancel,
    )
    .await;
    assert_eq!(stopped.unwrap_err(), BwError::Cancelled);
    assert!(!dir.path().join("bw-cli").exists());

    // Stopped while unpacking a download that is already there: the half-written program
    // is removed and the old one, if any, is not replaced.
    std::fs::write(dir.path().join("bw-test.zip"), &zip).unwrap();
    let cancel = Cancel::new();
    let stop_when_checking = |stage: PrepareStage| {
        if stage == PrepareStage::Checking {
            cancel.cancel();
        }
    };
    let stopped = ensure_cli_within(
        dir.path(),
        &base,
        "bw-test.zip",
        &expected,
        1024 * 1024,
        &stop_when_checking,
        &cancel,
    )
    .await;
    assert_eq!(stopped.unwrap_err(), BwError::Cancelled);
    assert!(!dir.path().join("bw.partial").exists());
    assert!(!dir.path().join("bw").exists());
}

/// Downloads the real pinned release through `ensure_cli` and runs it, through the client's
/// own way of running it (the cleared environment, `--nointeraction`), three times: its
/// version, its status, and `encode` reading standard input. None of the three signs in or
/// contacts a vault. Run by hand:
///
/// ```text
/// cargo test -p authexodus-core --test bitwarden -- --ignored --nocapture the_real_tool
/// ```
///
/// Set `AUTHEXODUS_BW_TEST_DIR` to keep the download in a folder of your choosing.
#[tokio::test]
#[ignore]
async fn the_real_tool_starts_under_the_cleared_environment() {
    use authexodus_core::bitwarden::download::CLI_VERSION;
    use base64::Engine;
    let temp = tempfile::tempdir().unwrap();
    let dir = std::env::var_os("AUTHEXODUS_BW_TEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.path().to_path_buf());
    let binary = authexodus_core::bitwarden::ensure_cli(&dir.join("bw-cli"))
        .await
        .expect("the pinned release downloads and verifies");
    let data = dir.join("bw-data");
    std::fs::create_dir_all(&data).unwrap();
    let client = CliClient::new(binary.path.clone(), data).expecting_sha256(binary.sha256);

    let version = client.probe(&["--version"], None).await.unwrap();
    println!("bw --version -> {}", version.trim());
    assert_eq!(version.trim(), CLI_VERSION);

    let status = client.probe(&["status"], None).await.unwrap();
    println!("bw status -> {}", status.trim());
    let status: serde_json::Value = serde_json::from_str(status.trim()).unwrap();
    assert_eq!(status["status"], "unauthenticated");

    let payload = r#"{"name":"Authy import"}"#;
    let encoded = client.probe(&["encode"], Some(payload)).await.unwrap();
    println!("bw encode -> {}", encoded.trim());
    assert_eq!(
        encoded.trim(),
        base64::engine::general_purpose::STANDARD.encode(payload)
    );
}
