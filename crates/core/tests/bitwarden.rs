//! Bitwarden integration tests against a fake client (package 1D). Synthetic data only.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use authexodus_core::bitwarden::cli::{classify_failure, parse_login_items};
use authexodus_core::bitwarden::download::ensure_cli_from;
use authexodus_core::bitwarden::{
    apply, propose, BwClient, BwError, CliClient, Confidence, Decision, LoginOutcome, Region,
    SetTotp, VaultLogin,
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
        let existing = s
            .logins
            .iter()
            .find(|l| l.id == item_id)
            .map(|l| l.has_totp);
        match existing {
            None => return Err(BwError::Cli("no such item".into())),
            Some(true) => return Ok(SetTotp::AlreadyHasCode),
            Some(false) => {}
        }
        let failure = tick(&mut s);
        if failure.as_ref().is_none_or(|(_, persist)| *persist) {
            s.totp_values.insert(item_id.into(), otpauth.into());
            s.logins
                .iter_mut()
                .find(|l| l.id == item_id)
                .unwrap()
                .has_totp = true;
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
        _: &str,
    ) -> Result<(), BwError> {
        let mut s = self.0.lock().unwrap();
        let failure = tick(&mut s);
        if failure.as_ref().is_none_or(|(_, persist)| *persist) {
            s.folder_titles.push(title.into());
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
    let tokens: Vec<Token> = (0..12)
        .map(|i| tok(&format!("t{i}"), &format!("Svc{i}"), None, None))
        .collect();
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
    let r = apply(&fake, &tokens, &decisions, &no_progress()).await;
    assert_eq!(r.attached, 1);
    assert_eq!(r.kept, vec!["Has Code".to_string()]);
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
        // A third run changes nothing.
        let writes = fake.writes();
        let third = apply(&fake, &tokens, &decisions, &no_progress()).await;
        assert_eq!((third.attached, third.created, third.failed), (0, 0, None));
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
    assert!(!msg.contains("SessionExpired"));
    assert_eq!(r.attached, 2);
    assert_eq!(fake.writes(), 3, "nothing is attempted after the failure");
}

#[tokio::test]
async fn skip_and_existing_titles_are_counted_as_skipped() {
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
    assert_eq!((r.created, r.skipped, r.failed), (0, 2, None));
    assert_eq!(fake.0.lock().unwrap().synced, 1, "syncs first");
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
    assert_eq!(path, dir.path().join("bw"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"#!/bin/sh\necho pretend bw\n"
    );
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
    assert_eq!(again, path);
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
    assert!(path.exists());
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

    assert_eq!(c.set_totp("item-1", uri).await.unwrap(), SetTotp::Attached);
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
        c.set_totp("item-1", uri).await.unwrap(),
        SetTotp::AlreadyHasCode
    );
    assert!(
        !sb.bin_dir.join("edit.stdin").exists(),
        "no edit when a code exists"
    );
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
    assert_eq!(sent["folderId"], "f2");
    assert_eq!(sent["login"]["username"], "sam@example.test");
    assert!(!sb.log("args.log").contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(sb.log("create.stdin").trim(), "ENCODEDJSON");
}
