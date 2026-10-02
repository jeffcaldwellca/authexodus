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

/// (key as it appears in a token, extra patterns to search for as well). A pattern containing a
/// dot is a host suffix (`live.com` matches `login.live.com`, never `livenation.com`); one
/// without is a whole word of the login name or a whole label of a host. A match that rests only
/// on one of these is never better than `Low` confidence: the user confirms it.
const ALIASES: &[(&str, &[&str])] = &[
    (
        "amazon web services",
        &["aws", "amazonaws.com", "aws.amazon.com"],
    ),
    (
        "microsoft",
        &[
            "microsoft.com",
            "live.com",
            "office.com",
            "microsoftonline.com",
        ],
    ),
    ("google", &["google.com", "gmail.com"]),
    ("gmail", &["google.com", "gmail.com"]),
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

struct Keys {
    own: Vec<String>,
    alias: Vec<String>,
}

fn search_keys(token: &Token) -> Keys {
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
    let mut own: Vec<String> = Vec::new();
    let mut alias: Vec<String> = Vec::new();
    for r in raw {
        let k = norm(r);
        if k.chars().count() < 3 {
            continue;
        }
        for (from, to) in ALIASES {
            if has_word_run(&k, from) {
                alias.extend(to.iter().map(|s| s.to_string()));
            }
        }
        own.push(k);
    }
    own.sort();
    own.dedup();
    alias.sort();
    alias.dedup();
    alias.retain(|a| !own.contains(a));
    Keys { own, alias }
}

fn host_has_suffix(host: &str, suffix: &str) -> bool {
    let host = host.to_lowercase();
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Whole words of the login name, or whole labels of a host; never part of a word.
fn key_hits(key: &str, name_norm: &str, hosts: &[String]) -> bool {
    if key.contains('.') {
        return hosts.iter().any(|h| host_has_suffix(h, key));
    }
    let host_norms = hosts.iter().map(|h| norm(h));
    if has_word_run(name_norm, key) || host_norms.clone().any(|h| has_word_run(&h, key)) {
        return true;
    }
    // "Stack Overflow" vs stackoverflow.com: a multi-word key, squashed, must be a whole word
    // or label by itself.
    if key.contains(' ') {
        let compact: String = key.split(' ').collect();
        return name_norm.split(' ').any(|w| w == compact)
            || host_norms
                .into_iter()
                .any(|h| h.split(' ').any(|w| w == compact));
    }
    false
}

/// `Some(alias_only)` when the login matches the token's service.
fn service_match(keys: &Keys, login: &VaultLogin) -> Option<bool> {
    let name = norm(&login.name);
    if keys.own.iter().any(|k| key_hits(k, &name, &login.hosts)) {
        Some(false)
    } else if keys.alias.iter().any(|k| key_hits(k, &name, &login.hosts)) {
        Some(true)
    } else {
        None
    }
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

/// (index in `vault`, score, match rests only on an alias).
type Scored = (usize, u32, bool);

/// Service-matching logins for one token, best first (own-key matches before alias-only ones,
/// vault order on ties).
fn scored(token: &Token, keys: &Keys, vault: &[VaultLogin]) -> Vec<Scored> {
    let mut v: Vec<Scored> = vault
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let alias_only = service_match(keys, l)?;
            let mut score = SERVICE_POINTS;
            if same_username(token, l) {
                score += USERNAME_POINTS;
            }
            Some((i, score, alias_only))
        })
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));
    v
}

/// Propose a decision for every token, in the order of `tokens`.
///
/// A login is proposed for at most one token. Tokens are settled strongest evidence first, so an
/// exact (service + username) match wins its login no matter where in the list it sits; a token
/// whose only candidates were taken becomes `CreateNew` with `Low` confidence and the taken
/// logins listed, so the user is asked.
pub fn propose(tokens: &[Token], vault: &[VaultLogin]) -> Vec<Proposal> {
    let keys: Vec<Keys> = tokens.iter().map(search_keys).collect();
    let scores: Vec<Vec<Scored>> = tokens
        .iter()
        .zip(&keys)
        .map(|(t, k)| scored(t, k, vault))
        .collect();

    // Strongest first, input order on ties.
    let mut order: Vec<usize> = (0..tokens.len()).collect();
    order.sort_by_key(|&i| {
        let best = scores[i]
            .iter()
            .filter(|(l, _, _)| !vault[*l].has_totp)
            .map(|(_, s, _)| *s)
            .max()
            .unwrap_or(0);
        (std::cmp::Reverse(best), i)
    });

    let mut claimed: HashSet<usize> = HashSet::new();
    let mut out: Vec<Option<Proposal>> = vec![None; tokens.len()];

    for i in order {
        let candidates: Vec<String> = scores[i]
            .iter()
            .map(|(l, _, _)| vault[*l].id.clone())
            .collect();
        let free: Vec<Scored> = scores[i]
            .iter()
            .copied()
            .filter(|(l, _, _)| !vault[*l].has_totp && !claimed.contains(l))
            .collect();
        let taken_by_another = scores[i]
            .iter()
            .any(|(l, _, _)| !vault[*l].has_totp && claimed.contains(l));

        let (decision, confidence) = match free.first() {
            Some(&(best, top, alias_only)) => {
                claimed.insert(best);
                let tied = free
                    .iter()
                    .filter(|(_, s, a)| *s == top && *a == alias_only)
                    .count();
                let confidence = if tied == 1 && !taken_by_another && !alias_only {
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
        assert!(search_keys(&token("t", "jeff@example.com", None))
            .own
            .is_empty());
        assert!(search_keys(&token("t", "ab", None)).own.is_empty());
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
