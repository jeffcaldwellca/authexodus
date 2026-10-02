//! `apply()`: attach or create, never overwrite, safe to re-run (package 1D).

use std::collections::HashSet;

use crate::export::otpauth_uri;
use crate::types::Token;

use super::{BwClient, BwError, CodeMark, Decision, SetTotp};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub attached: usize,
    pub created: usize,
    pub skipped: usize,
    /// Titles of tokens whose login already had a different authenticator key, left untouched.
    /// (A login that already holds this token's own key counts as attached: it is done.)
    pub kept: Vec<String>,
    /// A plain-language message when the run stopped early; everything before it stays done.
    pub failed: Option<String>,
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
        BwError::Input(detail) | BwError::Unsupported(detail) => format!("{detail} {RERUN}"),
    }
}

/// The title each decision would be created under, by position in `decisions`. Tokens that share
/// a title get " (2)", " (3)" ... in the order the decisions list them, so two tokens never
/// collapse into one login and a re-run maps every token to the same title as before.
fn unique_titles(tokens: &[Token], decisions: &[(String, Decision)]) -> Vec<String> {
    let base: Vec<Option<&str>> = decisions
        .iter()
        .map(|(id, d)| match d {
            Decision::CreateNew => tokens
                .iter()
                .find(|t| &t.id == id)
                .map(|t| t.title.as_str()),
            _ => None,
        })
        .collect();
    let all: HashSet<&str> = base.iter().flatten().copied().collect();
    let mut used: HashSet<String> = HashSet::new();
    base.iter()
        .map(|b| {
            let Some(b) = b else { return String::new() };
            let mut title = (*b).to_string();
            let mut n = 1;
            while used.contains(&title) || (n > 1 && all.contains(title.as_str())) {
                n += 1;
                title = format!("{b} ({n})");
            }
            used.insert(title.clone());
            title
        })
        .collect()
}

/// Apply the user's decisions. Syncs first, so anything a failed earlier run did create is seen.
/// Stops at the first Bitwarden error; `progress` gets one plain line per step.
///
/// Safe to run again, with the same decisions or with new ones: a login that already holds a
/// token's code is counted as attached, not written to; and no login is created for a token
/// whose code some login in the vault already holds, whatever that login is called.
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

    // Every code the vault holds already, so that a token moved by an earlier run (to a login
    // of any name, by this app or by hand) is never given a second login.
    let mut present: HashSet<CodeMark> = client
        .list_logins()
        .await?
        .into_iter()
        .filter_map(|login| login.code)
        .collect();

    let titles = unique_titles(tokens, decisions);

    for (n, (token_id, decision)) in decisions.iter().enumerate() {
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
                        present.extend(CodeMark::of_secret(token.secret.expose()));
                        progress(format!("Attached {}", token.title));
                    }
                    SetTotp::AlreadySet => {
                        report.attached += 1;
                        progress(format!("{} already has this code", token.title));
                    }
                    SetTotp::AlreadyHasCode => {
                        report.kept.push(token.title.clone());
                        progress(format!("Kept the existing code for {}", token.title));
                    }
                }
            }
            Decision::CreateNew => {
                let title = &titles[n];
                if existing.contains(title) {
                    report.skipped += 1;
                    progress(format!("{title} is already in the import folder"));
                    continue;
                }
                let mark = CodeMark::of_secret(token.secret.expose());
                if mark.is_some_and(|mark| present.contains(&mark)) {
                    report.skipped += 1;
                    progress(format!("{title} already has this code in Bitwarden"));
                    continue;
                }
                client
                    .create_in_import_folder(title, token.username.as_deref(), &otpauth_uri(token))
                    .await?;
                existing.insert(title.clone());
                present.extend(mark);
                report.created += 1;
                progress(format!("Created {title}"));
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
