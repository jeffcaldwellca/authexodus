//! `apply()`: attach or create, never overwrite, safe to re-run (package 1D).

use std::collections::HashSet;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::types::Token;

use super::{BwClient, BwError, Decision, SetTotp};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub attached: usize,
    pub created: usize,
    pub skipped: usize,
    /// Titles of tokens whose login already had an authenticator key, left untouched.
    pub kept: Vec<String>,
    /// A plain-language message when the run stopped early; everything before it stays done.
    pub failed: Option<String>,
}

/// Everything except RFC 3986 unreserved characters is escaped.
const URI_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

// reconcile with export::otpauth_uri at merge
fn otpauth_uri(t: &Token) -> String {
    let mut uri = format!(
        "otpauth://totp/{}?secret={}",
        utf8_percent_encode(&t.name, URI_ESCAPE),
        t.secret.expose()
    );
    if let Some(issuer) = t.issuer.as_deref().filter(|i| !i.is_empty()) {
        uri.push_str(&format!(
            "&issuer={}",
            utf8_percent_encode(issuer, URI_ESCAPE)
        ));
    }
    let digits = if t.digits == 0 { 6 } else { t.digits };
    let period = if t.period == 0 { 30 } else { t.period };
    uri.push_str(&format!("&digits={digits}&period={period}"));
    uri
}

fn plain_message(e: &BwError) -> String {
    const RERUN: &str = "Everything already done is kept; run it again to finish the rest.";
    match e {
        BwError::SessionExpired => format!(
            "Your Bitwarden session ended. Sign in again, then run this again. {RERUN}"
        ),
        BwError::Server(_) => format!(
            "Bitwarden's server had a problem or could not be reached. Wait a moment, then run this again. {RERUN}"
        ),
        BwError::Cli(detail) => format!("Bitwarden reported a problem: {detail}. {RERUN}"),
        BwError::Download(_) | BwError::ChecksumMismatch => {
            format!("The Bitwarden tool could not be prepared. {RERUN}")
        }
    }
}

/// Apply the user's decisions. Syncs first, so anything a failed earlier run did create is seen.
/// Stops at the first Bitwarden error; `progress` gets one plain line per step.
pub async fn apply(
    client: &dyn BwClient,
    tokens: &[Token],
    decisions: &[(String, Decision)],
    progress: &(dyn Fn(String) + Sync),
) -> ApplyReport {
    let mut report = ApplyReport::default();
    match run(client, tokens, decisions, progress, &mut report).await {
        Ok(()) => progress("Done.".to_string()),
        Err(e) => report.failed = Some(plain_message(&e)),
    }
    report
}

async fn run(
    client: &dyn BwClient,
    tokens: &[Token],
    decisions: &[(String, Decision)],
    progress: &(dyn Fn(String) + Sync),
    report: &mut ApplyReport,
) -> Result<(), BwError> {
    progress("Syncing with Bitwarden".to_string());
    client.sync().await?;

    let needs_titles = decisions
        .iter()
        .any(|(_, d)| matches!(d, Decision::CreateNew));
    let mut existing: HashSet<String> = if needs_titles {
        client.import_folder_titles().await?.into_iter().collect()
    } else {
        HashSet::new()
    };

    for (token_id, decision) in decisions {
        let Some(token) = tokens.iter().find(|t| &t.id == token_id) else {
            report.skipped += 1;
            continue;
        };
        match decision {
            Decision::Skip => report.skipped += 1,
            Decision::Attach { item_id } => {
                match client.set_totp(item_id, &otpauth_uri(token)).await? {
                    SetTotp::Attached => {
                        report.attached += 1;
                        progress(format!("Attached {}", token.title));
                    }
                    SetTotp::AlreadyHasCode => {
                        report.kept.push(token.title.clone());
                        progress(format!("Kept the existing code for {}", token.title));
                    }
                }
            }
            Decision::CreateNew => {
                if existing.contains(&token.title) {
                    report.skipped += 1;
                    progress(format!("{} is already in the import folder", token.title));
                    continue;
                }
                client
                    .create_in_import_folder(
                        &token.title,
                        token.username.as_deref(),
                        &otpauth_uri(token),
                    )
                    .await?;
                existing.insert(token.title.clone());
                report.created += 1;
                progress(format!("Created {}", token.title));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Secret;

    #[test]
    fn uri_escapes_name_and_issuer_and_omits_missing_issuer() {
        let mut t = Token {
            id: "1".into(),
            title: "t".into(),
            name: "a b&c:d".into(),
            issuer: Some("Ex Ample".into()),
            username: None,
            secret: Secret::new("JBSWY3DPEHPK3PXP".into()),
            digits: 6,
            period: 30,
        };
        assert_eq!(
            otpauth_uri(&t),
            "otpauth://totp/a%20b%26c%3Ad?secret=JBSWY3DPEHPK3PXP&issuer=Ex%20Ample&digits=6&period=30"
        );
        t.issuer = None;
        assert!(!otpauth_uri(&t).contains("issuer"));
    }
}
