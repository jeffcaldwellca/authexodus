//! `propose()`: match tokens to existing vault logins (package 1D).
//!
//! Scoring per (token, login): a service key found in the login's name or one of its hosts is +3;
//! the login's username equalling the token's username is +2. Only a service match makes a login a
//! candidate: a shared username alone (usually the user's one email address) says nothing about
//! which service a code belongs to, so it never causes an attach.

use std::collections::HashSet;

use crate::types::Token;

use super::VaultLogin;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Attach { item_id: String },
    CreateNew,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub token_id: String,
    pub decision: Decision,
    pub confidence: Confidence,
    /// Ids of every login that matched the service, best first (including ones that already have
    /// a code, which are listed but never chosen).
    pub candidates: Vec<String>,
}

const SERVICE_POINTS: u32 = 3;
const USERNAME_POINTS: u32 = 2;

/// (key as it appears in a token, extra keys to search for as well).
const ALIASES: &[(&str, &[&str])] = &[
    ("amazon web services", &["aws", "amazon"]),
    ("microsoft", &["microsoft", "live", "office"]),
    ("google", &["google", "gmail"]),
    ("gmail", &["google", "gmail"]),
];

/// Lowercase, every run of non-alphanumerics becomes one space.
fn norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut gap = true;
    for c in s.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
            gap = false;
        } else if !gap {
            out.push(' ');
            gap = true;
        }
    }
    out.trim_end().to_string()
}

fn has_word_run(haystack: &str, needle: &str) -> bool {
    format!(" {haystack} ").contains(&format!(" {needle} "))
}

fn search_keys(token: &Token) -> Vec<String> {
    let mut raw: Vec<&str> = Vec::new();
    if let Some(issuer) = token.issuer.as_deref() {
        raw.push(issuer);
    }
    // "GitHub: someone@x.com" and "GitHub (someone)" both mean "GitHub"; a bare address means
    // nothing about the service.
    let name = token.name.split([':', '(']).next().unwrap_or("");
    if !name.contains('@') {
        raw.push(name);
    }
    let mut keys: Vec<String> = Vec::new();
    for r in raw {
        let k = norm(r);
        if k.chars().count() < 3 {
            continue;
        }
        for (from, to) in ALIASES {
            if has_word_run(&k, from) {
                keys.extend(to.iter().map(|s| s.to_string()));
            }
        }
        keys.push(k);
    }
    keys.sort();
    keys.dedup();
    keys
}

fn key_hits(key: &str, text_norm: &str) -> bool {
    if has_word_run(text_norm, key) {
        return true;
    }
    // "Stack Overflow" vs stackoverflow.com; only for keys long enough not to hit by accident.
    let compact_key: String = key.split(' ').collect();
    compact_key.chars().count() >= 5
        && text_norm
            .split(' ')
            .collect::<String>()
            .contains(&compact_key)
}

fn service_match(keys: &[String], login: &VaultLogin) -> bool {
    let name = norm(&login.name);
    let hosts: Vec<String> = login.hosts.iter().map(|h| norm(h)).collect();
    keys.iter()
        .any(|k| key_hits(k, &name) || hosts.iter().any(|h| key_hits(k, h)))
}

fn same_username(token: &Token, login: &VaultLogin) -> bool {
    match (token.username.as_deref(), login.username.as_deref()) {
        (Some(a), Some(b)) => {
            let (a, b) = (a.trim(), b.trim());
            !a.is_empty() && a.eq_ignore_ascii_case(b)
        }
        _ => false,
    }
}

/// Service-matching logins for one token: (index in `vault`, score), best first, vault order on ties.
fn scored(token: &Token, keys: &[String], vault: &[VaultLogin]) -> Vec<(usize, u32)> {
    let mut v: Vec<(usize, u32)> = vault
        .iter()
        .enumerate()
        .filter(|(_, l)| service_match(keys, l))
        .map(|(i, l)| {
            let mut score = SERVICE_POINTS;
            if same_username(token, l) {
                score += USERNAME_POINTS;
            }
            (i, score)
        })
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

/// Propose a decision for every token, in the order of `tokens`.
///
/// A login is proposed for at most one token. Tokens are settled strongest evidence first, so an
/// exact (service + username) match wins its login no matter where in the list it sits; a token
/// whose only candidates were taken becomes `CreateNew` with `Low` confidence and the taken
/// logins listed, so the user is asked.
pub fn propose(tokens: &[Token], vault: &[VaultLogin]) -> Vec<Proposal> {
    let keys: Vec<Vec<String>> = tokens.iter().map(search_keys).collect();
    let scores: Vec<Vec<(usize, u32)>> = tokens
        .iter()
        .zip(&keys)
        .map(|(t, k)| scored(t, k, vault))
        .collect();

    // Strongest first, input order on ties.
    let mut order: Vec<usize> = (0..tokens.len()).collect();
    order.sort_by_key(|&i| {
        let best = scores[i]
            .iter()
            .filter(|(l, _)| !vault[*l].has_totp)
            .map(|(_, s)| *s)
            .max()
            .unwrap_or(0);
        (std::cmp::Reverse(best), i)
    });

    let mut claimed: HashSet<usize> = HashSet::new();
    let mut out: Vec<Option<Proposal>> = vec![None; tokens.len()];

    for i in order {
        let candidates: Vec<String> = scores[i]
            .iter()
            .map(|(l, _)| vault[*l].id.clone())
            .collect();
        let free: Vec<(usize, u32)> = scores[i]
            .iter()
            .copied()
            .filter(|(l, _)| !vault[*l].has_totp && !claimed.contains(l))
            .collect();
        let taken_by_another = scores[i]
            .iter()
            .any(|(l, _)| !vault[*l].has_totp && claimed.contains(l));

        let (decision, confidence) = match free.first() {
            Some(&(best, top)) => {
                claimed.insert(best);
                let tied = free.iter().filter(|(_, s)| *s == top).count();
                let confidence = if tied == 1 && !taken_by_another {
                    Confidence::High
                } else {
                    Confidence::Low
                };
                (
                    Decision::Attach {
                        item_id: vault[best].id.clone(),
                    },
                    confidence,
                )
            }
            None if taken_by_another => (Decision::CreateNew, Confidence::Low),
            None => (Decision::CreateNew, Confidence::High),
        };
        out[i] = Some(Proposal {
            token_id: tokens[i].id.clone(),
            decision,
            confidence,
            candidates,
        });
    }
    out.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_collapses_punctuation() {
        assert_eq!(norm("  Stack-Overflow.com / x "), "stack overflow com x");
    }

    #[test]
    fn short_or_address_names_make_no_keys() {
        assert!(search_keys(&token("t", "jeff@example.com", None)).is_empty());
        assert!(search_keys(&token("t", "ab", None)).is_empty());
    }

    fn token(id: &str, name: &str, issuer: Option<&str>) -> Token {
        Token {
            id: id.into(),
            title: name.into(),
            name: name.into(),
            issuer: issuer.map(Into::into),
            username: None,
            secret: crate::types::Secret::new("JBSWY3DPEHPK3PXP".into()),
            digits: 6,
            period: 30,
        }
    }
}
